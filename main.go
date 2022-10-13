package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/urfave/negroni"
	"github.com/xanzy/go-gitlab"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
)

// /////////////// LOGGING
func DebugLoggingMiddleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// do some stuff before
	fmt.Println(" ###### REQUEST #####")
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	lrw := NewResponseWriterWrapper(rw)

	next(lrw, r)

	fmt.Println(lrw)
}

// ResponseWriterWrapper struct is used to log the response
type ResponseWriterWrapper struct {
	w          *http.ResponseWriter
	body       *bytes.Buffer
	statusCode *int
}

// NewResponseWriterWrapper static function creates a wrapper for the http.ResponseWriter
func NewResponseWriterWrapper(w http.ResponseWriter) ResponseWriterWrapper {
	var buf bytes.Buffer
	var statusCode int = 200
	return ResponseWriterWrapper{
		w:          &w,
		body:       &buf,
		statusCode: &statusCode,
	}
}

func (rww ResponseWriterWrapper) Write(buf []byte) (int, error) {
	rww.body.Write(buf)
	return (*rww.w).Write(buf)
}

// Header function overwrites the http.ResponseWriter Header() function
func (rww ResponseWriterWrapper) Header() http.Header {
	return (*rww.w).Header()

}

// WriteHeader function overwrites the http.ResponseWriter WriteHeader() function
func (rww ResponseWriterWrapper) WriteHeader(statusCode int) {
	*rww.statusCode = statusCode
	(*rww.w).WriteHeader(statusCode)
}

func (rww ResponseWriterWrapper) String() string {
	var buf bytes.Buffer

	buf.WriteString("\nResponse: \n")

	buf.WriteString("Headers:")
	for k, v := range (*rww.w).Header() {
		buf.WriteString(fmt.Sprintf("%s: %v", k, v))
	}

	buf.WriteString(fmt.Sprintf("\nStatus Code: %d", *(rww.statusCode)))

	buf.WriteString("\nBody: \n")
	buf.WriteString(rww.body.String())
	return buf.String()
}

// /////////////// SETTINGS
var gitlab_url = os.Getenv("GITLAB_URL")
var rancher_url = os.Getenv("RANCHER_URL")
var listen_address = os.Getenv("LISTEN_ADDRESS")
var rancher_urls = make(map[string]string)

// /////////////// MAIN
func main() {
	if listen_address == "" {
		listen_address = "127.0.0.1:8888"
	}

	router := httprouter.New()
	router.GET("/login/oauth/authorize", oauthAuthorize)
	router.POST("/login/oauth/access_token", oauthAccessToken)
	router.GET("/api/v3/user", apiV3User)
	router.GET("/api/v3/user/:id", apiV3UserId)
	router.GET("/api/v3/users/:id", apiV3SearchUsers)
	router.GET("/api/v3/teams/:id", apiV3TeamsId)
	router.GET("/api/v3/search/users", apiV3SearchUsers)

	n := negroni.New() // Includes some default middlewares
	n.Use(negroni.HandlerFunc(DebugLoggingMiddleware))
	n.UseHandler(router)

	fmt.Println("Listening to " + listen_address)
	if err := http.ListenAndServe(listen_address, n); err != nil {
		panic(err)
	}
}

// /////////////// API
func oauthAuthorize(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	redirect_uri := req.URL.Query().Get("redirect_uri")
	client_id := req.URL.Query().Get("client_id")
	rancher_urls[client_id] = redirect_uri

	fmt.Println("redirect_uri", redirect_uri, "client_id", client_id, rancher_urls)

	v := req.URL.Query()
	v.Add("response_type", "code")
	v.Add("scope", "read_api")
	target := gitlab_url + "/oauth/authorize?" + v.Encode()
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

func oauthAccessToken(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	req.ParseForm()
	v := req.URL.Query()
	v.Add("grant_type", "authorization_code")

	client_id := req.Form.Get("client_id")

	_, found := rancher_urls[client_id]
	if found {
		fmt.Println("Using url from cache")
		v.Add("redirect_uri", rancher_urls[client_id])
	} else {
		v.Add("redirect_uri", rancher_url+"/verify-auth")
	}

	fmt.Println("found", found, "client_id", client_id, rancher_urls)

	target := gitlab_url + "/oauth/token?" + v.Encode()
	http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}

func apiV3User(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	gitlabClient := createGitlabClient(req)
	gitlabUser, _, err := gitlabClient.Users.CurrentUser()
	if err != nil {
		panic(err)
	}

	githubAccount := convertGitlabUserToAccount(gitlabUser)

	jsonStr, _ := json.Marshal(githubAccount)
	w.Write(jsonStr)
}

func apiV3UserId(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	// Workaround to deal with routing library
	if ps.ByName("id") == "orgs" {
		apiV3UserOrgs(w, req, ps)
		return
	}
	if ps.ByName("id") == "teams" {
		apiV3UserTeams(w, req, ps)
		return
	}

	gitlabClient := createGitlabClient(req)

	id, _ := strconv.Atoi(ps.ByName("id"))
	// user
	gitlabUser, _, err := gitlabClient.Users.GetUser(id, gitlab.GetUsersOptions{})
	if err != nil {
		panic(err)
	}

	githubAccount := convertGitlabUserToAccount(gitlabUser)
	jsonStr, _ := json.Marshal(githubAccount)
	w.Write(jsonStr)
}

func apiV3UserOrgs(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	result := make([]string, 0)

	jsonStr, _ := json.Marshal(result)
	w.Write(jsonStr)
}

func apiV3UserTeams(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	gitlabClient := createGitlabClient(req)
	allAvailable := false

	result := make([]Team, 0, 0)

	listGroupsOptions := &gitlab.ListGroupsOptions{
		ListOptions: gitlab.ListOptions{},
		// here, we only want to search for groups WHICH WE ARE MEMBER OF!!!
		AllAvailable: &allAvailable,
	}
	for {
		gitlabGroups, resp, err := gitlabClient.Groups.ListGroups(listGroupsOptions)
		if err != nil {
			panic(err)
		}

		for _, gitlabGroup := range gitlabGroups {
			team := convertGitlabGroupToTeam(gitlabGroup)
			result = append(result, *team)
		}

		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}

		// Update the page number to get the next page.
		listGroupsOptions.ListOptions.Page = resp.NextPage

	}
	jsonStr, _ := json.Marshal(result)
	w.Write(jsonStr)
}

func apiV3TeamsId(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {

	gitlabClient := createGitlabClient(req)

	id, _ := strconv.Atoi(ps.ByName("id"))

	gitlabGroup, _, err := gitlabClient.Groups.GetGroup(id, &gitlab.GetGroupOptions{})
	if err != nil {
		panic(err)
	}
	team := convertGitlabGroupToTeam(gitlabGroup)

	jsonStr, _ := json.Marshal(team)
	w.Write(jsonStr)
}

type searchResult struct {
	Items []*Account `json:"items"`
}

func apiV3SearchUsers(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
	query := req.URL.Query().Get("q")

	// Support for old search
	if len(query) == 0 {
		query = ps.ByName("id")
	}
	gitlabClient := createGitlabClient(req)

	searchResult := &searchResult{
		Items: make([]*Account, 0),
	}

	shouldSearchUsers := true
	shouldSearchOrgs := true
	if strings.Contains(query, "type:org") {
		shouldSearchUsers = false
		shouldSearchOrgs = true
		query = strings.ReplaceAll(query, "type:org", "")
	}

	if shouldSearchOrgs {
		allAvailable := true
		gitlabGroups, _, err := gitlabClient.Groups.ListGroups(&gitlab.ListGroupsOptions{
			Search: &query,
			// we want to find ALL groups (which are not fully private)
			AllAvailable: &allAvailable,
		})
		if err != nil {
			panic(err)
		}
		for _, gitlabGroup := range gitlabGroups {
			githubOrg := convertGitlabGroupToAccount(gitlabGroup)
			searchResult.Items = append(searchResult.Items, githubOrg)
		}
	}

	if shouldSearchUsers {
		gitlabUsers, _, err := gitlabClient.Users.ListUsers(&gitlab.ListUsersOptions{
			Search: &query,
		})
		if err != nil {
			panic(err)
		}
		for _, gitlabUser := range gitlabUsers {
			githubAccount := convertGitlabUserToAccount(gitlabUser)
			searchResult.Items = append(searchResult.Items, githubAccount)
		}
	}

	jsonStr, _ := json.Marshal(searchResult)
	w.Write(jsonStr)
}

///////////////// HELPERS

// https://docs.github.com/en/free-pro-team@latest/rest/reference/users#get-the-authenticated-user
// copied from https://github.com/rancher/rancher/blob/2506427ba7bd31edf12f7110b7fdb8b2defe8eb3/pkg/auth/providers/github/github_account.go#L12
type Account struct {
	ID        int    `json:"id,omitempty"`
	Login     string `json:"login,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url,omitempty"`
	// "Type" must be "user", "team", oder "org"
	Type string `json:"type,omitempty"`
}

// Team defines properties a team on github has
type Team struct {
	ID           int                    `json:"id,omitempty"`
	Organization map[string]interface{} `json:"organization,omitempty"`
	Name         string                 `json:"name,omitempty"`
	AvatarURL    string                 `json:"avatar_url"`
	Slug         string                 `json:"slug,omitempty"`
}

func createGitlabClient(req *http.Request) *gitlab.Client {
	authorizationHeader := req.Header.Get("Authorization")
	t := strings.Split(authorizationHeader, " ")
	token := t[1]
	gitlabClient, err := gitlab.NewOAuthClient(token, gitlab.WithBaseURL(gitlab_url+"/api/v4"))
	if err != nil {
		panic(err)
	}
	return gitlabClient
}

func convertGitlabUserToAccount(gitlabUser *gitlab.User) *Account {
	return &Account{
		ID:        gitlabUser.ID,
		Login:     gitlabUser.Username,
		Name:      gitlabUser.Name,
		AvatarURL: getImage(gitlabUser.AvatarURL),
		HTMLURL:   "",
		Type:      "user",
	}
}

func convertGitlabGroupToAccount(gitlabGroup *gitlab.Group) *Account {
	return &Account{
		ID:        gitlabGroup.ID,
		Login:     gitlabGroup.Path,
		Name:      gitlabGroup.Name,
		AvatarURL: getImage(gitlabGroup.AvatarURL),
		HTMLURL:   "",
		Type:      "team",
	}
}

func convertGitlabGroupToTeam(gitlabGroup *gitlab.Group) *Team {
	org := make(map[string]interface{})
	org["login"] = gitlabGroup.Path
	org["avatar_url"] = getImage(gitlabGroup.AvatarURL)

	return &Team{
		ID:           gitlabGroup.ID,
		Organization: org,
		Name:         gitlabGroup.Name,
		Slug:         gitlabGroup.Path,
		AvatarURL:    getImage(gitlabGroup.AvatarURL),
	}
}

func getImage(image string) string {
	if image != "" {
		return image
	}
	return "https://secure.gravatar.com/avatar/18742e6f4409949dfc6a91e95d539f7b?s=80&d=identicon&s=80"
}
