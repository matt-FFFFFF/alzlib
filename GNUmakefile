# Create a test coverage report and launch a browser to view it
testcover:
	if [ -f "coverage.out" ]; then rm coverage.out; fi
	go test -coverprofile=coverage.out -covermode=count
	go tool cover -html=coverage.out

# Create a test coverage report in an html file
testcoverfile:
	if [ -f "coverage.out" ]; then rm coverage.out; fi
	if [ -f "coverage.html" ]; then rm coverage.html; fi
	go test -coverprofile=coverage.out -covermode=count
	go tool cover -html=coverage.out -o=coverage.html

# Converts from Terraform's ${{var}} syntax to Go's {{.Var} syntax
# Double dollar sign here as `make` first expands the command line, so need to escape it
converttestdata:
	find ./testdata/lib -type f -exec sed -i 's|$${\([^}]*\)}|{{\.\1}}|g' {} \;
	find ./testdata/lib -type f -exec sed -i 's|{{\.\(.\)|\U&|g' {} \;
