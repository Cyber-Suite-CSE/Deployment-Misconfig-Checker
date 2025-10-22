"use client"

import { useState } from "react"
import { Globe, AlertTriangle, Database, Zap, Code, Settings, Info, Menu, X, Shield } from "lucide-react"

interface SidebarProps {
  activeNav: string
  onNavChange: (nav: string) => void
}

const navItems = [
  { id: "web-domain", label: "Web Domain Scanner", icon: Globe },
  { id: "cve", label: "CVE Scanner", icon: AlertTriangle },
  { id: "database", label: "Database Scanner", icon: Database },
  { id: "api", label: "API Discovery", icon: Zap },
  { id: "code", label: "Code Scanner", icon: Code },
  { id: "settings", label: "Settings", icon: Settings },
  { id: "about", label: "About", icon: Info },
]

export function Sidebar({ activeNav, onNavChange }: SidebarProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <>
      {/* Mobile Toggle */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-accent text-accent-foreground"
      >
        {isOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Sidebar */}
      <aside
        className={`${
          isOpen ? "w-64" : "w-0"
        } bg-sidebar border-r border-sidebar-border transition-all duration-300 flex flex-col overflow-hidden lg:w-64`}
      >
        {/* Logo */}
        <div className="p-6 border-b border-sidebar-border flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sidebar-primary flex items-center justify-center">
            <Shield size={24} className="text-sidebar-primary-foreground" />
          </div>
          <div className="flex-1">
            <h1 className="font-bold text-lg text-sidebar-foreground">SecSuite</h1>
            <p className="text-xs text-sidebar-foreground/60">Offensive Security</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = activeNav === item.id
            return (
              <button
                key={item.id}
                onClick={() => {
                  onNavChange(item.id)
                  setIsOpen(false)
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                  isActive
                    ? "bg-sidebar-primary text-sidebar-primary-foreground shadow-lg"
                    : "text-sidebar-foreground hover:bg-sidebar-accent/10"
                }`}
              >
                <Icon size={20} />
                <span className="font-medium text-sm">{item.label}</span>
              </button>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-sidebar-border text-xs text-sidebar-foreground/60">
          <p>v1.0.0</p>
          <p>© 2025 SecSuite</p>
        </div>
      </aside>

      {/* Mobile Overlay */}
      {isOpen && <div className="lg:hidden fixed inset-0 bg-black/50 z-40" onClick={() => setIsOpen(false)} />}
    </>
  )
}
