# rancher-gitlab-proxy
Authenticate Rancher users from Gitlab instance. Uses proxy simulating GitHub API translating calls to Gitlab API

All credits goes to https://sandstorm.de/de/blog/post/making-rancher-2-and-gitlab-oauth-authentication-work-together.html

# Installation using docker

1. Use `docker-compose.yaml` to run rancher-gitlab-proxy next to gitlab container. 
1. Configure Gitlab - add config option from `gitlab.rb`
1. Create Gitlab application with `read_api` scope
1. Configure Rancher to use GitHub authentication, set enterprise host to your Gitlab url, fill in Application ID and Secret from Gitlab.
1. Working Gitlab Rancher authentication :-)
