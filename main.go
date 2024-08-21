// Package main - Ortelius CLI for adding Component Versions to the DB from the CI/CD pipeline
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/araddon/dateparse"
	"github.com/docker/buildx/util/imagetools"
	resty "github.com/go-resty/resty/v2"
	"github.com/mkideal/cli"
	model "github.com/ortelius/scec-commons/model"
	toml "github.com/pelletier/go-toml/v2"
)

const (
	LicenseFile int = 0 // LicenseFile is used to read the License file
	SwaggerFile int = 1 // SwaggerFile is used to read the Swagger/OpenApi file
	ReadmeFile  int = 2 // ReadmeFile is used to read the Readme file
)

const (
	baseName                   string = "BASENAME"
	buildDate                  string = "BLDDATE"
	buildID                    string = "BUILDID"
	buildNum                   string = "BUILDNUM"
	buildURL                   string = "BUILDURL"
	chart                      string = "CHART"
	chartNamespace             string = "CHARTNAMESPACE"
	chartRepo                  string = "CHARTREPO"
	chartRepoURL               string = "CHARTREPOURL"
	chartVersion               string = "CHARTVERSION"
	discordChannel             string = "DISCORDCHANNEL"
	dockerRepo                 string = "DOCKERREPO"
	dockerSha                  string = "DOCKERSHA"
	dockerTag                  string = "DOCKERTAG"
	gitCommit2                 string = "GITCOMMIT"
	gitRepo2                   string = "GITREPO"
	gitTag2                    string = "GITTAG"
	gitURL2                    string = "GITURL"
	gitBranch                  string = "GIT_BRANCH"
	gitBranchCreateCommit      string = "GIT_BRANCH_CREATE_COMMIT"
	gitBranchCreateTimestamp   string = "GIT_BRANCH_CREATE_TIMESTAMP"
	gitBranchParent            string = "GIT_BRANCH_PARENT"
	gitCommit                  string = "GIT_COMMIT"
	gitCommittersCnt           string = "GIT_COMMITTERS_CNT"
	gitCommitAuthors           string = "GIT_COMMIT_AUTHORS"
	gitCommitTimestamp         string = "GIT_COMMIT_TIMESTAMP"
	gitContribPercentage       string = "GIT_CONTRIB_PERCENTAGE"
	gitLinesAdded              string = "GIT_LINES_ADDED"
	gitLinesDeleted            string = "GIT_LINES_DELETED"
	gitLinesTotal              string = "GIT_LINES_TOTAL"
	gitOrg                     string = "GIT_ORG"
	gitPreviousComponentCommit string = "GIT_PREVIOUS_COMPONENT_COMMIT"
	gitRepo                    string = "GIT_REPO"
	gitRepoProject             string = "GIT_REPO_PROJECT"
	gitSignedOffBy             string = "GIT_SIGNED_OFF_BY"
	gitTag                     string = "GIT_TAG"
	gitTotalCommittersCnt      string = "GIT_TOTAL_COMMITTERS_CNT"
	gitURL                     string = "GIT_URL"
	gitVerifyCommit            string = "GIT_VERIFY_COMMIT"
	hipchatChannel             string = "HIPCHATCHANNEL"
	pagerdutyBusinessURL       string = "PAGERDUTYBUSINESSURL"
	pagerdutyURL               string = "PAGERDUTYURL"
	repository                 string = "REPOSITORY"
	serviceOwner               string = "SERVICEOWNER"
	shortSha                   string = "SHORT_SHA"
	slackChannel               string = "SLACKCHANNEL"
)

var licenseFiles = []string{"LICENSE", "LICENSE.md", "license", "license.md"}
var swaggerFiles = []string{"swagger.yaml", "swagger.yml", "swagger.json", "openapi.json", "openapi.yaml", "openapi.yml"}
var readmeFiles = []string{"README", "README.md", "readme", "readme.md"}

func findExisingFile(filenames []string) string {
	for _, filename := range filenames {
		if _, err := os.Stat(filename); err == nil {
			return filename
		}
	}
	return ""
}

func getSBOMFromImage(imageRef string) string {

	// Create a new context.
	ctx := context.Background()

	// Create a new image inspect client.
	var inspectClient *imagetools.Printer
	var err error

	if inspectClient, err = imagetools.NewPrinter(ctx, imagetools.Opt{}, imageRef, "{{ json .SBOM.SPDX }}"); err != nil {
		fmt.Printf("Could not load SBOM from image %s: %v", imageRef, err)
		return ""
	}

	buf := new(bytes.Buffer)
	inspectClient.Print(false, buf)

	// Convert string to io.Reader
	str := buf.String()
	reader := strings.NewReader(str)

	// Decode the image SPDX SBOM
	var spdxSBOM *sbom.SBOM
	var format sbom.FormatID
	var version string

	spdxdecoder := spdxjson.NewFormatDecoder()
	if spdxSBOM, format, version, err = spdxdecoder.Decode(reader); err != nil {
		fmt.Printf("Could not convert image %s: %v", imageRef, err)
		return ""
	}
	fmt.Printf("Converted %s from %s %s", imageRef, format, version)

	// Create a CycloneDX Encoder
	var cyclonedx sbom.FormatEncoder

	if cyclonedx, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig()); err != nil {
		fmt.Printf("Error converting to CycloneDX %s: %v", imageRef, err)
		return ""
	}

	// Convert the SPDX SBOM ot CycloneDX SBOM
	buf = new(bytes.Buffer)
	_ = cyclonedx.Encode(buf, *spdxSBOM)
	return buf.String()
}

func getProvenanceFromImage(imageRef string) string {

	// Create a new context.
	ctx := context.Background()

	// Create a new image inspect client.
	var inspectClient *imagetools.Printer
	var err error

	if inspectClient, err = imagetools.NewPrinter(ctx, imagetools.Opt{}, imageRef, "{{ json .Provenance }}"); err != nil {
		fmt.Printf("Could not load Provenance from image %s: %v", imageRef, err)
		return ""
	}

	buf := new(bytes.Buffer)
	inspectClient.Print(false, buf)

	// Convert string to io.Reader
	return buf.String()
}

// resolveVars will resolve the ${var} with a value from the component.toml or environment variables
func resolveVars(val string, data map[interface{}]interface{}) string {

	for k, v := range data {
		switch t := v.(type) {
		case map[string]interface{}:
			for a, b := range t {
				val = strings.ReplaceAll(val, "${"+a+"}", b.(string))
			}
		case string:
			val = strings.ReplaceAll(val, "${"+k.(string)+"}", v.(string))
		}
	}

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		val = strings.ReplaceAll(val, "${"+pair[0]+"}", pair[1])
	}
	return val
}

// getCompToml reads the component.toml file and assignes the key/values to the fields in the CompAttrs struct
//
//nolint:gocyclo
func getCompToml(derivedAttrs map[string]string) (*model.CompAttrs, map[string]string) {
	attrs := model.NewCompAttrs()
	extraAttrs := make(map[string]string, 0)

	for k, v := range derivedAttrs {

		if _, found := os.LookupEnv(strings.ToUpper(k)); !found {
			os.Setenv(strings.ToUpper(k), v)
		}

		switch strings.ToUpper(k) {
		case baseName:
			attrs.Basename = v
		case buildDate:
			t, _ := dateparse.ParseAny(v)
			attrs.BuildDate = t
		case buildID:
			attrs.BuildID = v
		case buildNum:
			attrs.BuildNum = v
		case buildURL:
			attrs.BuildURL = v
		case chart:
			attrs.Chart = v
		case chartNamespace:
			attrs.ChartNamespace = v
		case chartRepo:
			attrs.ChartRepo = v
		case chartRepoURL:
			attrs.ChartRepoURL = v
		case chartVersion:
			attrs.ChartVersion = v
		case discordChannel:
			attrs.DiscordChannel = v
		case dockerRepo:
			attrs.DockerRepo = v
		case dockerSha:
			attrs.DockerSha = v
		case dockerTag:
			attrs.DockerTag = v
		case shortSha:
			attrs.GitCommit = v
		case gitBranch:
			attrs.GitBranch = v
		case gitBranchParent:
			attrs.GitBranchParent = v
		case gitBranchCreateCommit:
			attrs.GitBranchCreateCommit = v
		case gitBranchCreateTimestamp:
			t, _ := dateparse.ParseAny(v)
			attrs.GitBranchCreateTimestamp = t
		case gitCommit:
			attrs.GitCommit = v
		case gitCommit2:
			attrs.GitCommit = v
		case gitCommitAuthors:
			attrs.GitCommitAuthors = v
		case gitCommitTimestamp:
			t, _ := dateparse.ParseAny(v)
			attrs.GitCommitTimestamp = t
		case gitCommittersCnt:
			attrs.GitCommittersCnt = v
		case gitContribPercentage:
			attrs.GitContribPercentage = v
		case gitLinesAdded:
			attrs.GitLinesAdded = v
		case gitLinesDeleted:
			attrs.GitLinesDeleted = v
		case gitLinesTotal:
			attrs.GitLinesTotal = v
		case gitOrg:
			attrs.GitOrg = v
		case gitPreviousComponentCommit:
			attrs.GitPrevCompCommit = v
		case gitRepoProject:
			attrs.GitRepoProject = v
		case gitRepo:
			attrs.GitRepo = v
		case gitRepo2:
			attrs.GitRepo = v
		case gitTag:
			attrs.GitTag = v
		case gitTag2:
			attrs.GitTag = v
		case gitTotalCommittersCnt:
			attrs.GitTotalCommittersCnt = v
		case gitURL:
			attrs.GitURL = v
		case gitURL2:
			attrs.GitURL = v
		case gitVerifyCommit:
			attrs.GitVerifyCommit = false
			if v == "1" {
				attrs.GitVerifyCommit = true
			}
		case gitSignedOffBy:
			attrs.GitSignedOffBy = v
		case hipchatChannel:
			attrs.HipchatChannel = v
		case pagerdutyBusinessURL:
			attrs.PagerdutyBusinessURL = v
		case pagerdutyURL:
			attrs.PagerdutyURL = v
		case repository:
			attrs.Repository = v
		case serviceOwner:
			attrs.ServiceOwner.Name, attrs.ServiceOwner.Domain = makeName(v)
		case slackChannel:
			attrs.SlackChannel = v

		}
	}

	f, err := os.ReadFile("component.toml")

	if err != nil {
		log.Println(err)
		return attrs, extraAttrs
	}

	var data map[interface{}]interface{}

	err = toml.Unmarshal(f, &data)

	if err != nil {
		log.Println(err)
		return attrs, extraAttrs
	}

	for k, v := range data {
		switch t := v.(type) {
		case map[string]interface{}:
			{
				// Look for well known attributes from component.toml [Attributes] section and assign them
				for a, b := range t {
					switch strings.ToUpper(a) {
					case buildDate:
						t, _ := dateparse.ParseAny(resolveVars(b.(string), data))
						attrs.BuildDate = t
					case buildID:
						attrs.BuildID = resolveVars(b.(string), data)
					case buildURL:
						attrs.BuildURL = resolveVars(b.(string), data)
					case chart:
						attrs.Chart = resolveVars(b.(string), data)
					case chartNamespace:
						attrs.ChartNamespace = resolveVars(b.(string), data)
					case chartRepo:
						attrs.ChartRepo = resolveVars(b.(string), data)
					case chartRepoURL:
						attrs.ChartRepoURL = resolveVars(b.(string), data)
					case chartVersion:
						attrs.ChartVersion = resolveVars(b.(string), data)
					case discordChannel:
						attrs.DiscordChannel = resolveVars(b.(string), data)
					case dockerRepo:
						attrs.DockerRepo = resolveVars(b.(string), data)
					case dockerSha:
						attrs.DockerSha = resolveVars(b.(string), data)
					case dockerTag:
						attrs.DockerTag = resolveVars(b.(string), data)
					case gitCommit:
						attrs.GitCommit = resolveVars(b.(string), data)
					case gitRepo:
						attrs.GitRepo = resolveVars(b.(string), data)
					case gitTag:
						attrs.GitTag = resolveVars(b.(string), data)
					case gitURL:
						attrs.GitURL = resolveVars(b.(string), data)
					case hipchatChannel:
						attrs.HipchatChannel = resolveVars(b.(string), data)
					case pagerdutyBusinessURL:
						attrs.PagerdutyBusinessURL = resolveVars(b.(string), data)
					case pagerdutyURL:
						attrs.PagerdutyURL = resolveVars(b.(string), data)
					case repository:
						attrs.Repository = resolveVars(b.(string), data)
					case serviceOwner:
						attrs.ServiceOwner.Name, attrs.ServiceOwner.Domain = makeName(resolveVars(b.(string), data))
					case slackChannel:
						attrs.SlackChannel = resolveVars(b.(string), data)
					default:
						extraAttrs[strings.ToUpper(a)] = resolveVars(b.(string), data)
					}
				}
			}
		case string:

			// Look for well known attributes at the root of the component.toml and assign them
			switch strings.ToUpper(k.(string)) {
			case buildDate:
				t, _ := dateparse.ParseAny(resolveVars(v.(string), data))
				attrs.BuildDate = t
			case buildID:
				attrs.BuildID = resolveVars(v.(string), data)
			case buildURL:
				attrs.BuildURL = resolveVars(v.(string), data)
			case chart:
				attrs.Chart = resolveVars(v.(string), data)
			case chartNamespace:
				attrs.ChartNamespace = resolveVars(v.(string), data)
			case chartRepo:
				attrs.ChartRepo = resolveVars(v.(string), data)
			case chartRepoURL:
				attrs.ChartRepoURL = resolveVars(v.(string), data)
			case chartVersion:
				attrs.ChartVersion = resolveVars(v.(string), data)
			case discordChannel:
				attrs.DiscordChannel = resolveVars(v.(string), data)
			case dockerRepo:
				attrs.DockerRepo = resolveVars(v.(string), data)
			case dockerSha:
				attrs.DockerSha = resolveVars(v.(string), data)
			case dockerTag:
				attrs.DockerTag = resolveVars(v.(string), data)
			case gitCommit:
				attrs.GitCommit = resolveVars(v.(string), data)
			case gitRepo:
				attrs.GitRepo = resolveVars(v.(string), data)
			case gitTag:
				attrs.GitTag = resolveVars(v.(string), data)
			case gitURL:
				attrs.GitURL = resolveVars(v.(string), data)
			case hipchatChannel:
				attrs.HipchatChannel = resolveVars(v.(string), data)
			case pagerdutyBusinessURL:
				attrs.PagerdutyBusinessURL = resolveVars(v.(string), data)
			case pagerdutyURL:
				attrs.PagerdutyURL = resolveVars(v.(string), data)
			case repository:
				attrs.Repository = resolveVars(v.(string), data)
			case serviceOwner:
				attrs.ServiceOwner.Name, attrs.ServiceOwner.Domain = makeName(resolveVars(v.(string), data))
			case slackChannel:
				attrs.SlackChannel = resolveVars(v.(string), data)
			default:
				extraAttrs[strings.ToUpper(k.(string))] = resolveVars(v.(string), data)
			}
		}
	}
	return attrs, extraAttrs
}

// gatherFile finds and reads the license, swagger or readme into a string array
func gatherFile(filetype int) []string {

	lines := make([]string, 0)
	filename := ""

	switch filetype {
	case LicenseFile:
		filename = findExisingFile(licenseFiles)
	case SwaggerFile:
		filename = findExisingFile(swaggerFiles)
	case ReadmeFile:
		filename = findExisingFile(readmeFiles)
	}

	if len(filename) > 0 {
		data, err := os.ReadFile(filename)
		if err != nil {
			log.Println(err)
			return lines
		}

		lines = strings.Split(string(data), "\n")

		return lines
	}
	return lines
}

// runGit executes a shell command and returns the output as a string
func runGit(cmdline string) string {
	cmd := exec.Command("sh", "-c", cmdline)
	output, _ := cmd.CombinedOutput()

	return strings.TrimSuffix(string(output), "\n")
}

// getWithDefault is a helper function for finding a key in a map and return a default value if the key is not found
func getWithDefault(m map[string]string, key string, defaultStr string) string {
	if x, found := m[key]; found {
		return x
	}
	return defaultStr
}

// getDerived will run commands in the current working directory to derive data mainly from git
func getDerived() map[string]string {
	mapping := make(map[string]string, 0)

	runGit("git fetch --unshallow 2>/dev/null")

	mapping["BLDDATE"] = time.Now().UTC().String()
	mapping["SHORT_SHA"] = runGit("git log --oneline -n 1 | cut -d' '  -f1")
	mapping["GIT_COMMIT"] = runGit("git log --oneline -n 1 | cut -d' '  -f1")
	mapping["GIT_VERIFY_COMMIT"] = runGit("git verify-commit " + getWithDefault(mapping, "GIT_COMMIT", "") + " 2>&1 | grep -i 'Signature made' | wc -l | tr -d ' '")
	mapping["GIT_SIGNED_OFF_BY"] = runGit("git log -1 " + getWithDefault(mapping, "GIT_COMMIT", "") + " | grep 'Signed-off-by:' | cut -d: -f2 | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/&/\\&amp;/g; s/</\\&lt;/g; s/>/\\&gt;/g;'")
	mapping["BUILDNUM"] = runGit("git log --oneline | wc -l | tr -d \" \"")
	mapping["GIT_REPO"] = runGit("git config --get remote.origin.url | sed 's#:#/#' | awk -F/ '{print $(NF-1)\"/\"$NF}'| sed 's/.git$//'")
	mapping["GIT_REPO_PROJECT"] = runGit("git config --get remote.origin.url | sed 's#:#/#' | awk -F/ '{print $NF}' | sed 's/.git$//'")
	mapping["GIT_ORG"] = runGit("git config --get remote.origin.url | sed 's#:#/#' | awk -F/ '{print $(NF-1)}'")
	mapping["GIT_URL"] = runGit("git config --get remote.origin.url")
	mapping["GIT_BRANCH"] = runGit("git rev-parse --abbrev-ref HEAD")
	mapping["GIT_COMMIT_TIMESTAMP"] = runGit("git log --pretty='format:%cd' --date=rfc " + getWithDefault(mapping, "SHORT_SHA", "") + " | head -1")
	mapping["GIT_BRANCH_PARENT"] = runGit("git show-branch -a 2>/dev/null | sed \"s/].*//\" | grep \"\\*\" | grep -v \"$(git rev-parse --abbrev-ref HEAD)\" | head -n1 | sed \"s/^.*\\[//\"")
	mapping["GIT_BRANCH_CREATE_COMMIT"] = runGit("git log --oneline --reverse " + getWithDefault(mapping, "GIT_BRANCH_PARENT", "main") + ".." + getWithDefault(mapping, "GIT_BRANCH", "main") + " | head -1 | awk -F' ' '{print $1}'")
	mapping["GIT_BRANCH_CREATE_TIMESTAMP"] = runGit("git log --pretty='format:%cd'  --date=rfc " + getWithDefault(mapping, "GIT_BRANCH_CREATE_COMMIT", "HEAD") + " | head -1")
	mapping["GIT_COMMIT_AUTHORS"] = runGit("git rev-list --remotes --pretty --since='" + getWithDefault(mapping, "GIT_BRANCH_CREATE_TIMESTAMP", "") + "' --until='" + getWithDefault(mapping, "GIT_COMMIT_TIMESTAMP", "") + "' | grep -i 'Author:' | grep -v dependabot | awk -F'[:<>]' '{print $3}' | sed 's/^ //' | sed 's/ $//' | sort -u | tr '\n' ',' | sed 's/,$//'")

	if len(getWithDefault(mapping, "GIT_COMMIT_AUTHORS", "")) == 0 {
		mapping["GIT_COMMIT_AUTHORS"] = runGit("git log | grep -i 'Author:' | grep -v dependabot | awk -F'[:<>]' '{print $3}' | sed 's/^ //' | sed 's/ $//' | sort -u | tr '\n' ',' | sed 's/,$//'")
	}

	mapping["GIT_COMMITTERS_CNT"] = fmt.Sprintf("%d", len(strings.Split(getWithDefault(mapping, "GIT_COMMIT_AUTHORS", ""), ",")))

	committersCnt, _ := strconv.Atoi(getWithDefault(mapping, "GIT_COMMITTERS_CNT", "0"))
	committersCntTotal, _ := strconv.Atoi(getWithDefault(mapping, "GIT_TOTAL_COMMITTERS_CNT", "0"))

	if committersCntTotal > 0 {
		mapping["GIT_CONTRIB_PERCENTAGE"] = fmt.Sprintf("%d", int64(float64(committersCnt/committersCntTotal)*100))
	} else {
		mapping["GIT_CONTRIB_PERCENTAGE"] = "0"
	}

	mapping["GIT_LINES_TOTAL"] = runGit("wc -l $(git ls-files) | grep total | awk -F' ' '{print $1}'")

	if len(getWithDefault(mapping, "GIT_PREVIOUS_COMPONENT_COMMIT", "")) > 0 {
		gitcommit := getWithDefault(mapping, "GIT_PREVIOUS_COMPONENT_COMMIT", "")
		mapping["GIT_LINES_ADDED"] = runGit("git diff --stat " + getWithDefault(mapping, "SHORT_SHA", "") + " " + gitcommit + " | grep changed | cut -d\" \" -f5")
		mapping["GIT_LINES_DELETED"] = runGit("git diff --stat " + getWithDefault(mapping, "SHORT_SHA", "") + " " + gitcommit + " | grep changed | cut -d\" \" -f7")
	} else {
		mapping["GIT_PREVIOUS_COMPONENT_COMMIT"] = ""
		mapping["GIT_LINES_ADDED"] = "0"
		mapping["GIT_LINES_DELETED"] = "0"
	}

	if len(getWithDefault(mapping, "GIT_COMMIT_TIMESTAMP", "")) > 0 {
		t, _ := dateparse.ParseAny(getWithDefault(mapping, "GIT_COMMIT_TIMESTAMP", ""))
		mapping["GIT_COMMIT_TIMESTAMP"] = t.UTC().String()
	}

	if len(getWithDefault(mapping, "GIT_BRANCH_CREATE_TIMESTAMP", "")) > 0 {
		t, _ := dateparse.ParseAny(getWithDefault(mapping, "GIT_BRANCH_CREATE_TIMESTAMP", ""))
		mapping["GIT_BRANCH_CREATE_TIMESTAMP"] = t.UTC().String()
	}

	cwd, _ := os.Getwd()
	mapping["BASENAME"] = path.Base(cwd)

	if len(getWithDefault(mapping, "COMPNAME", "")) == 0 {
		mapping["COMPNAME"] = getWithDefault(mapping, "GIT_REPO_PROJECT", "")
	}

	return mapping
}

// makeUser takes a string and creates a User struct.  Handles setting the domain if the string contains dots.
func makeName(name string) (string, *model.Domain) {
	domain := model.NewDomain()

	parts := strings.Split(name, ".")
	if len(parts) > 1 {
		name = parts[len(parts)-1]
		parts = parts[:len(parts)-1]

		domain.Name = strings.Join(parts, ".")
	}
	return name, domain
}

// gatherEvidence collects data from the component.toml and git repo for the component version
func gatherEvidence(URL string, userID string, password string, sbom string) {

	user := model.NewUser()
	createTime := time.Now().UTC()
	user.Name, user.Domain = makeName(userID)

	license := model.NewLicense()
	license.Content = gatherFile(LicenseFile)

	swagger := model.NewSwagger()
	swagger.Content = json.RawMessage([]byte(strings.Join(gatherFile(SwaggerFile), "\n")))

	readme := model.NewReadme()
	readme.Content = gatherFile(ReadmeFile)

	derivedAttrs := getDerived()
	attrs, tomlVars := getCompToml(derivedAttrs)

	//	appname := getWithDefault(tomlVars, "APPLICATION", "")
	//	appversion := getWithDefault(tomlVars, "APPLICATION_VERSION", "")

	compver := model.NewComponentVersionDetails()

	compname := getWithDefault(tomlVars, "NAME", "")
	compvariant := getWithDefault(tomlVars, "VARIANT", "")
	compversion := getWithDefault(tomlVars, "VERSION", "")

	compver.Attrs = attrs
	compver.CompType = "docker"
	compver.Created = createTime
	compver.Creator = user
	compver.License = license
	compver.Name, compver.Domain = makeName(compname)
	compver.Variant = compvariant
	compver.Version = compversion
	compver.Owner.Name, compver.Owner.Domain = makeName(userID)
	compver.Readme = readme
	compver.Swagger = swagger

	client := resty.New()

	if _, err := os.Stat(sbom); err == nil {
		if data, err := os.ReadFile(sbom); err == nil {
			sbom := model.NewSBOM()
			sbom.Content = json.RawMessage(data)

			// POST Struct, default is JSON content type. No need to set one
			var res model.ResponseKey
			resp, err := client.R().
				SetBody(sbom).
				SetResult(&res).
				Post(URL + "/msapi/sbom")

			fmt.Printf("%s=%v\n", resp, err)
			fmt.Printf("KEY=%s\n", res.Key)

			compver.SBOMKey = res.Key
		}
	}

	imageRef := ""
	if len(attrs.DockerRepo) > 0 {
		if len(attrs.DockerSha) > 0 {
			imageRef = fmt.Sprintf("%s@sha256:%s", attrs.DockerRepo, attrs.DockerSha)
		} else if len(attrs.DockerTag) > 0 {
			imageRef = fmt.Sprintf("%s:%s", attrs.DockerRepo, attrs.DockerTag)
		}

		sbomString := getSBOMFromImage(imageRef)

		if len(sbomString) > 0 {
			sbom := model.NewSBOM()
			sbom.Content = json.RawMessage(sbomString)

			// POST Struct, default is JSON content type. No need to set one
			var res model.ResponseKey
			resp, err := client.R().
				SetBody(sbom).
				SetResult(&res).
				Post(URL + "/msapi/sbom")

			fmt.Printf("%s=%v\n", resp, err)
			fmt.Printf("KEY=%s\n", res.Key)

			compver.SBOMKey = res.Key
		}

		provenanceString := getProvenanceFromImage(imageRef)

		if len(provenanceString) > 0 {
			provenance := model.NewProvenance()
			provenance.Content = json.RawMessage(provenanceString)

			// POST Struct, default is JSON content type. No need to set one
			var res model.ResponseKey
			resp, err := client.R().
				SetBody(provenance).
				SetResult(&res).
				Post(URL + "/msapi/provenance")

			fmt.Printf("%s=%v\n", resp, err)
			fmt.Printf("KEY=%s\n", res.Key)

			compver.ProvenanceKey = res.Key
		}

	}

	// POST Struct, default is JSON content type. No need to set one
	var res model.ResponseKey
	resp, err := client.R().
		SetBody(compver).
		SetResult(&res).
		Post(URL + "/msapi/compver")

	fmt.Printf("%s=%v\n", resp, err)
	fmt.Printf("KEY=%s\n", res.Key)

	compver.Key = res.Key
}

// main is the entrypoint for the CLI.  Takes --user and --pass parameters
func main() {
	type argT struct {
		cli.Helper
		URL      string `cli:"*url" usage:"Console Url (required)"`
		UserID   string `cli:"*user" usage:"User id (required)"`
		Password string `cli:"*pass" usage:"User password (required)"`
		SBOM     string `cli:"sbom" usage:"CycloneDX Json Filename"`
	}

	os.Exit(cli.Run(new(argT), func(ctx *cli.Context) error {
		argv := ctx.Argv().(*argT)

		gatherEvidence(argv.URL, argv.UserID, argv.Password, argv.SBOM)
		return nil
	}))
}
