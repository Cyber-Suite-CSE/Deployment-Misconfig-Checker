"use client"

import React from "react"

import { useState } from "react"
import { Sidebar } from "./sidebar"
import { TopBar } from "./top-bar"
import { ScanBar } from "./scan-bar"

interface DashboardLayoutProps {
  activeNav: string
  onNavChange: (nav: string) => void
  userEmail: string
  onLogout: () => void
  children: React.ReactNode
}

export function DashboardLayout({ activeNav, onNavChange, userEmail, onLogout, children }: DashboardLayoutProps) {
  const [domain, setDomain] = useState("")
  const [isExecuting, setIsExecuting] = useState(false)

  const showScanBar = ["web-domain", "cve", "database", "api", "code"].includes(activeNav)

  const handleExecute = () => {
    setIsExecuting(true)
    // Simulate execution
    setTimeout(() => setIsExecuting(false), 2000)
  }

  return (
    <div className="flex h-screen bg-background">
      {/* Left Sidebar */}
      <Sidebar activeNav={activeNav} onNavChange={onNavChange} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar with User Profile */}
        <TopBar userEmail={userEmail} onLogout={onLogout} />

        {/* Scan Bar (conditional) */}
        {showScanBar && (
          <ScanBar domain={domain} onDomainChange={setDomain} onExecute={handleExecute} isExecuting={isExecuting} />
        )}

        {/* Main Content */}
        <main className="flex-1 overflow-auto">
          <div className="p-6">
            {React.isValidElement(children)
              ? React.cloneElement(children as React.ReactElement<{ domain: string }>, { domain })
              : children}
          </div>
        </main>
      </div>
    </div>
  )
}
