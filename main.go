package main

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"trivy2mysql/cmd"
)

func main() {
	cmd.Execute()
}
