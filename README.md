# Secure_DevOps

## Report Link
https://www.overleaf.com/read/nwcbygmnzvqq#592669

## AWS Server Details
Jenkins - 18.197.123.154\
Python - 3.120.192.5


## Pipeline Deployment Steps

### Installing Jenkins

- sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
- echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null
- sudo apt-get update
- sudo apt-get install jenkins

- sudo apt update
- sudo apt install fontconfig openjdk-17-jre
- java -version
openjdk version "17.0.8" 2023-07-18
OpenJDK Runtime Environment (build 17.0.8+7-Debian-1deb12u1)
OpenJDK 64-Bit Server VM (build 17.0.8+7-Debian-1deb12u1, mixed mode, sharing)

- sudo systemctl start jenkins

- http://127.0.0.1:8080

- /var/lib/jenkins/secrets/initialAdminPassword [Password file for jenkins]

- Then install docker in the system.

### Installing plugins in Jenkins

- SSH Agent
- Blue Ocean

- Check if the git is installed or not. Set it up in Tools.

### Installing and Running trufflehog

- docker run gesellix/trufflehog --json https://github.com/DHARMIKR/sample_devsecops.git >> trufflehog.txt


### Note: always install every library manually before running the pipeline.

### Setting up Sonarqube

- Run sonarqube docker container [docker run -d -p 9000:9000 sonarqube] [default credentials - admin:admin]
- Install "sonarqube scanner" plugin in Jenkins
- Go to "account/security" in Sonarqube and generate a token from there [sqa_35679b5d7b097d411c6bd0d86cc324d7a18f7992]
- Go to "manage/configure" in jenkins and configure the sonarqube there by giving name, server URL and authentication token
- Add sonar automatic installation in "manage jenkins/ Tools"
- Don't forget to add sonar token into the command of sonar scanner in jenkins
