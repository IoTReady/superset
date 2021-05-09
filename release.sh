#!/bin/bash
REPO=513722356193.dkr.ecr.ap-south-1.amazonaws.com/superset
git add .
git commit 
commit_hash=`git rev-parse HEAD`
login_cmd=`aws ecr get-login --region ap-south-1 --no-include-email`
eval $login_cmd
docker build -t $REPO:${commit_hash::7} .
docker push $REPO:${commit_hash::7}
