#!/bin/sh

if [ -z "$TRAVIS_PULL_REQUEST" ] || [ "$TRAVIS_PULL_REQUEST" == "false" ]
then
  if [ "$TRAVIS_BRANCH" == "staging" ] || [ "$TRAVIS_BRANCH" == "production" ]
  then

    # install and set up awscli
    curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
    unzip awscli-bundle.zip
    ./awscli-bundle/install -b ~/bin/aws
    export PATH=~/bin:$PATH

    # add AWS_ACCOUNT_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY env vars
    eval $(aws ecr get-login --region us-east-1 --no-include-email)

    # build and push images
    # set up env vars
    COMMIT=${TRAVIS_COMMIT:0:8}
    BRANCH=${TRAVIS_BRANCH}

    # api
    if [ "$TRAVIS_BRANCH" == "staging" ]
    then
      DOCKERFILE=Dockerfile.stage
    else
      DOCKERFILE=Dockerfile.prod
    fi
    docker build $API_GIT_REPO -t $API_IMG_REPO:$COMMIT -f $DOCKERFILE
    docker tag $API_IMG_REPO:$COMMIT $IMG_REGISTRY/$API_IMG_REPO:$BRANCH
    docker push $IMG_REGISTRY/$API_IMG_REPO:$BRANCH
  
    # database
    if [ "$TRAVIS_BRANCH" == "staging" ]
    then
      docker build $DB_GIT_REPO -t $DB_IMG_REPO:$COMMIT -f Dockerfile
      docker tag $DB_IMG_REPO:$COMMIT $IMG_REGISTRY/$DB_IMG_REPO:$BRANCH
      docker push $IMG_REGISTRY/$DB_IMG_REPO:$BRANCH
    fi

    # swagger
    docker build $SWAGGER_GIT_REPO -t $SWAGGER_IMG_REPO:$COMMIT --build-arg SERVER_URL=${SERVER_URL} -f Dockerfile
    docker tag $SWAGGER_IMG_REPO:$COMMIT $IMG_REGISTRY/$SWAGGER_IMG_REPO:$BRANCH
    docker push $IMG_REGISTRY/$SWAGGER_IMG_REPO:$BRANCH
  fi
fi
