VERSION = `git rev-parse --short HEAD`
TO := _

ifdef BUILD_NUMBER
NUMBER = $(BUILD_NUMBER)
else
NUMBER = 1
endif

ifdef JOB_BASE_NAME
PROJECT_ENCODED_SLASH = $(subst %2F,$(TO),$(JOB_BASE_NAME))
PROJECT = $(subst /,$(TO),$(PROJECT_ENCODED_SLASH))
# Run on CI
COMPOSE = docker-compose -f docker-compose.yml -f docker-compose.ci.yml -p eve_auth_jwt_$(PROJECT)_$(NUMBER)
else
# Run Locally
COMPOSE = docker-compose -p eve_auth_jwt
endif

DEVPI_USER ?= dailymotion
DEVPI_PASS ?= test1234
DEVPI_INDEX ?= https://pypi.stg.dm.gg/dailymotion/dm2
DEVPI_PKG_NAME ?= eve-auth-jwt

PUBLISH_CMD = ./run.sh publish
PUBLISH_CMD += $(DEVPI_INDEX)
PUBLISH_CMD += $(DEVPI_USER)
PUBLISH_CMD += $(DEVPI_PASS)
PUBLISH_CMD += $(DEVPI_PKG_NAME)

PUBLISH_CMD := "$(PUBLISH_CMD)"

EXISTS_CMD = ./run.sh exists
EXISTS_CMD += $(DEVPI_INDEX)
EXISTS_CMD += $(DEVPI_USER)
EXISTS_CMD += $(DEVPI_PASS)
EXISTS_CMD += $(DEVPI_PKG_NAME)
EXISTS_CMD += $(DEVPI_PKG_VERSION)

EXISTS_CMD := "$(EXISTS_CMD)"

.PHONY: init
init:
	# This following command is used to provision the network
	$(COMPOSE) up --no-start --no-build format | true

.PHONY: format
format:
	$(COMPOSE) build format-imports
	$(COMPOSE) run format-imports
	$(COMPOSE) build format
	$(COMPOSE) run format


.PHONY: check-format
check-format:
	$(COMPOSE) build check-format-imports
	$(COMPOSE) run check-format-imports
	$(COMPOSE) build check-format
	$(COMPOSE) run check-format


.PHONY: style
style: check-format
	$(COMPOSE) build style
	$(COMPOSE) run style


.PHONY: shell
shell:
	$(COMPOSE) build shell
	$(COMPOSE) run shell


.PHONY: test-unit
test-unit:
	$(COMPOSE) build test-unit
	$(COMPOSE) run test-unit


.PHONY: test
test: test-unit


.PHONY: complexity
complexity:
	$(COMPOSE) build complexity
	$(COMPOSE) run complexity


.PHONY: security-sast
security-sast:
	$(COMPOSE) build security-sast
	$(COMPOSE) run security-sast


.PHONY: build-clean
build-clean:
	$(COMPOSE) build build-clean
	$(COMPOSE) run build-clean


.PHONY: build
build: build-clean
	$(COMPOSE) build build-package
	$(COMPOSE) run build-package


.PHONY: publish
publish:
	$(COMPOSE) pull
	$(COMPOSE) run --entrypoint $(PUBLISH_CMD) devpi


.PHONY: down
down:
	$(COMPOSE) down --volume


.PHONY: exists
exists:
	$(COMPOSE) run --entrypoint $(EXISTS_CMD) devpi


.PHONY: tag
tag:
	git tag $(PKG_VERSION)
	git push origin $(PKG_VERSION)


.PHONY: get-version
get-version:
	bash -c "cat setup.py |grep \"_VERSION =\" |egrep -o \"([0-9]+\\.[0-9]+\\.[0-9]+)\""


.PHONY: get-sandbox-version
get-sandbox-version:
	git fetch --tags
	git describe --tags


.PHONY: set-version
set-version:
	bash -c "sed -i \"s@_VERSION[ ]*=[ ]*[\\\"\'][0-9]\+\\.[0-9]\+\\.[0-9]\+[\\\"\'].*@_VERSION='$(PKG_VERSION)'@\" setup.py"


# Build Sonar properties file (sonar-project.properties)
# Set version with the short hash commit
prepare-sonar:
	cp sonar-project.properties.default sonar-project.properties
	echo "sonar.projectVersion=$(VERSION)" >> sonar-project.properties
