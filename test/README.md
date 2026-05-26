# End-to-end tests

Note: This is mostly copied from the tkey-ssh-agent and adapted with
some basic tests to get testing going. Todo is still to write more
tests, and make it run in CI.

A set of high-level end-to-end tests testing the behavior in
real-world-like scenarios from a user perspective.

A test framework, based on pytest, is used to set up and tear down
resources such as QEmu and other external resources.

## Running tests

To run all tests. Install dependencies and then run Pytest via Pipenv:

```
pipenv run pytest
```

Pytest will automatically detect and execute any function with a name
beginning with `test_` in any Python file beginning with `test_`.

Some custom command line options are available. For a list of
available options see "Custom options" section of:

```
pipenv run pytest --help
```

See the Pytest documentation for how to run single tests, a subset of
tests, etc.

### Dependencies

The tkeytest-py test utils containing prebuilt firmware and flash
image binaries, Python wrappers for external tools, and other tools is
included as a git submodule. Get the submodule by running:

```
git submodule update --init
```

Other Python dependencies are managed using Pipenv with `Pipfile` and
`Pipfile.lock`. To install the dependencies in a Pipenv virtualenv
run:

```
pipenv install
```

### Markers

Pytest markers can be used for documentation or filtering which tests
to run. The following custom pytest markers are defined:

- touch: Mark tests as requiring user interaction via touch sensor.
- issue: Mark tests with a reference to an issue.

## Writing tests

To add a test, add a function called `test_*` in a Python file called
`test_*.py`. Name the test function in a way that conveys what
behavior to test.

If a test needs to interact with a TKey the `tkey` Pytest fixture
can be used to spin up a QEmu instance. The emulated TKey is then
accessed through the `TKey` interface. Tests that use the `tkey`
fixture will automatically run once per platform, where the platform
is a Bellatrix, Bellatrix Unlocked, etc. See the fixture for a
specific list of platforms.

When tests need to interact with external resources, each resource is
wrapped in a driver class which all interactions go through. Processes
that need to run in the background implements a Python context manager
and can be used in `with`-statements.

### Development dependencies

Development dependencies, such as linter and typechecker, can be
installed in a Pipenv virtualenv with:

```
pipenv install --dev
```

### Linting

Linting, formatting and typechecking is done using ruff and mypy. For
invokation see the CI job `qemu-test` defined under
`../.github/workflows/`.

Configuration is kept in `pyproject.toml`.
