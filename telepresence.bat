@echo off
telepresence intercept idp --port 5100:80 -n idp --http-header all --env-file %userprofile%\\idp.env