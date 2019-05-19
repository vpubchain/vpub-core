#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

cd "build/particl-$HOST" || (echo "could not enter distdir build/particl-$HOST"; exit 1)

if [ "$RUN_UNIT_TESTS" = "true" ]; then
  BEGIN_FOLD unit-tests
  DOCKER_EXEC LD_LIBRARY_PATH=$TRAVIS_BUILD_DIR/depends/$HOST/lib make $MAKEJOBS check VERBOSE=1
  END_FOLD
fi

if [ $((`date +%s`-$START_TIME)) -gt $RUN_TESTS_TIMEOUT ]; then
  RUN_FUNCTIONAL_TESTS=false;
fi

echo $((`date +%s`-$START_TIME))
echo $RUN_TESTS_TIMEOUT
echo "$RUN_FUNCTIONAL_TESTS"

if [ "$RUN_FUNCTIONAL_TESTS" = "true" ]; then
  BEGIN_FOLD functional-tests
  DOCKER_EXEC test/functional/test_runner.py --ci --combinedlogslen=4000 --coverage --quiet --failfast --particl --insight --bitcoin
  END_FOLD
fi

if [ "$RUN_FUZZ_TESTS" = "true" ]; then
  BEGIN_FOLD fuzz-tests
  DOCKER_EXEC test/fuzz/test_runner.py -l DEBUG ${DIR_FUZZ_IN}
  END_FOLD
fi
