-----------LOGIN_USING_HEROKU_CLI-------------
heroku login
heroku container:login
----------------------------------------------
------PUBLISHING_TO_DOCKER_HEROKU_CLI---------
docker build -t dorset-api .
docker tag dorset-api registry.heroku.com/dorset-api/web
docker push registry.heroku.com/dorset-api/web
heroku container:push web -a dorset-api   
heroku container:release web -a dorset-api
----------------------------------------------