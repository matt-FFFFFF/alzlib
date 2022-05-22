# Create a test coverage report
testcover:
	if [ -f "coverage.out" ]; then rm coverage.txt; fi
	go test -coverprofile=coverage.out -covermode=count
	go tool cover -html=coverage.out
