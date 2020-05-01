#!/bin/bash -ex

readonly SCRIPT_DIR=$(dirname "$0")
readonly PROJECT_ROOT_DIR=$(dirname $SCRIPT_DIR)

PYLINT_ARGS="--rcfile=$PROJECT_ROOT_DIR/pylint/pylint.cfg"
PYCODESTYLE_ARGS="--max-line-length=120 --exclude=acm-cert.py --exclude=core/bin"

log () {
  echo '=========>' "$@"
}

usage () {
  echo
  echo "Usage $0: -d <list of directories containing code>"
  echo "  -d: Space separated list of directories containing code which should be analyzed"

  exit 1
}

CODE_DIRS=""
TEST_DIR="tests"

while getopts ":d:t:" opts;
do
  case "${opts}" in
    d)
      CODE_DIRS=${OPTARG}
      ;;
    t)
      TEST_DIR=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

upgrade_tools(){
  echo "Upgrade linting tools"

  pip --quiet install --upgrade pylint
  log 'Pylint version: ' && pylint --version

  pip --quiet install --upgrade pycodestyle
  log 'Pycodestyle version: ' && pycodestyle --version
}


main() {
  if [ -z "$CODE_DIRS" ]; then
    usage
  fi


  rc=0
  for code_dir in $CODE_DIRS ;
  do

    log "Analyzing code directory: $code_dir"

    if ! pycodestyle $PYCODESTYLE_ARGS "$code_dir" ;
    then
      rc=$((rc + 1))
    fi

    # Disable duplicate code check for directory containing tests
    if [[ "$code_dir" == "$TEST_DIR" ]] ;
    then
      PYLINT_ARGS="--disable duplicate-code $PYLINT_ARGS"
    fi

    if ! pylint $PYLINT_ARGS "$code_dir" ;
    then
      rc=$((rc + 1))
    fi

  done

  if [[ "$rc" != "0" ]];
  then
    log "Warnings found in code."

    return 1
  fi

}

main "$@"
