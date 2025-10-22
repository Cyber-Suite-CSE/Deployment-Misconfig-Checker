"use client"

import { useState, useEffect } from "react"
import { DashboardLayout } from "@/components/dashboard-layout"
import { WebDomainScanner } from "@/components/sections/web-domain-scanner"
import { CVEScanner } from "@/components/sections/cve-scanner"
import { DatabaseScanner } from "@/components/sections/database-scanner"
import { APIDiscovery } from "@/components/sections/api-discovery"
import { CodeScanner } from "@/components/sections/code-scanner"
import { Settings } from "@/components/sections/settings"
import { About } from "@/components/sections/about"

type NavigationItem = "web-domain" | "cve" | "database" | "api" | "code" | "settings" | "about"

export default function Home() {
  const [activeNav, setActiveNav] = useState<NavigationItem>("web-domain")
  const [userEmail, setUserEmail] = useState("user@example.com")
  const [domain, setDomain] = useState("")

  useEffect(() => {
    // Simulate loading user email from session/auth
    const savedEmail = localStorage.getItem("userEmail")
    if (savedEmail) {
      setUserEmail(savedEmail)
    }
  }, [])

  const renderContent = () => {
    switch (activeNav) {
      case "web-domain":
        return <WebDomainScanner domain={domain} />
      case "cve":
        return <CVEScanner domain={domain} />
      case "database":
        return <DatabaseScanner domain={domain} />
      case "api":
        return <APIDiscovery domain={domain} />
      case "code":
        return <CodeScanner domain={domain} />
      case "settings":
        return <Settings />
      case "about":
        return <About />
      default:
        return <WebDomainScanner domain={domain} />
    }
  }

  return (
    <DashboardLayout
      activeNav={activeNav}
      onNavChange={setActiveNav}
      userEmail={userEmail}
      onLogout={() => {
        localStorage.removeItem("userEmail")
        setUserEmail("user@example.com")
      }}
    >
      {renderContent()}
    </DashboardLayout>
  )
}
