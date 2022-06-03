# Automated tests

## Pytest

The tests done at a unit level are run via [pytest](https://docs.pytest.org/en/latest/index.html).

To run locally, start the [Devcontainer](../getting-started.md#develop-with-vs-code-remote-containers) and run:

```bash
cd tests
./run.sh
```

The helper script:

1. Runs the tests with `pytest`
2. Calculates test coverage with [`coverage`](https://coverage.readthedocs.io/en/latest/)
3. Generates a `coverage` report in HTML in a directory named `coverage`.

The report files include a local `.gitignore` file, so the entire directory is hidden from source control.

### Latest coverage report

We also make the latest (from `dev`) coverage report available online here: [Coverage report](./coverage)
