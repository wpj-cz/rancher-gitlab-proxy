# rancher-gitlab-proxy
Authenticate Rancher users from Gitlab instance. Uses proxy simulating GitHub API translating calls to Gitlab API

All credits goes to https://sandstorm.de/de/blog/post/making-rancher-2-and-gitlab-oauth-authentication-work-together.html

It is now not required to fill `RANCHER_URL` env variable. Rancher url is auto-detected from requests now. You can this way use same gitlab instance for several Rancher instances! :-)

Tested with Gitlab 15 and Rancher 2.6

# Installation using docker

1. Run `wpjsro/rancher-gitlab-proxy:latest` Docker image next to Gitlab. Set `GITLAB_URL`, see example `docker-compose.yaml`. 
1. Configure Gitlab - add config option from `gitlab.rb`
1. Create Gitlab application with `read_api` scope and `https://<RANCHER_URL>/verify-auth` redirect URL
1. Configure Rancher to use GitHub authentication, set enterprise host to your Gitlab url, fill in Application ID and Secret from Gitlab.
1. Working Gitlab Rancher authentication :-)
