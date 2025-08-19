package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "./reports/strider.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Query findings
	fmt.Println("=== SECURITY FINDINGS ===")
	rows, err := db.Query("SELECT rule_id, title, severity, category FROM findings LIMIT 10")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var ruleID, title, severity, category string
		err := rows.Scan(&ruleID, &title, &severity, &category)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Rule: %s | Title: %s | Severity: %s | Category: %s\n", ruleID, title, severity, category)
	}

	// Query pages
	fmt.Println("\n=== CRAWLED PAGES ===")
	rows2, err := db.Query("SELECT url, title, status_code FROM pages LIMIT 5")
	if err != nil {
		log.Fatal(err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var url, title string
		var statusCode int
		err := rows2.Scan(&url, &title, &statusCode)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("URL: %s | Title: %s | Status: %d\n", url, title, statusCode)
	}

	// Query reports
	fmt.Println("\n=== REPORTS ===")
	rows3, err := db.Query("SELECT session_id, total_findings, critical_count, high_count, medium_count, low_count FROM reports LIMIT 5")
	if err != nil {
		log.Fatal(err)
	}
	defer rows3.Close()

	for rows3.Next() {
		var sessionID string
		var total, critical, high, medium, low int
		err := rows3.Scan(&sessionID, &total, &critical, &high, &medium, &low)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Session: %s | Total: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n",
			sessionID, total, critical, high, medium, low)
	}

	// Count summary
	fmt.Println("\n=== DATABASE SUMMARY ===")
	var findingsCount, pagesCount, reportsCount int

	db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&findingsCount)
	db.QueryRow("SELECT COUNT(*) FROM pages").Scan(&pagesCount)
	db.QueryRow("SELECT COUNT(*) FROM reports").Scan(&reportsCount)

	fmt.Printf("Total Findings: %d\n", findingsCount)
	fmt.Printf("Total Pages: %d\n", pagesCount)
	fmt.Printf("Total Reports: %d\n", reportsCount)
}
