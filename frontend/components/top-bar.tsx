"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { LogOut, Moon, Sun, User } from "lucide-react"
import { useTheme } from "next-themes"

interface TopBarProps {
  userEmail: string
  onLogout: () => void
}

export function TopBar({ userEmail, onLogout }: TopBarProps) {
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div className="h-16 border-b border-border bg-card flex items-center justify-between px-6">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Offensive Security Suite</h2>
        </div>
      </div>
    )
  }

  return (
    <div className="h-16 border-b border-border bg-card flex items-center justify-between px-6">
      {/* Left side - Title */}
      <div>
        <h2 className="text-lg font-semibold text-foreground">Offensive Security Suite</h2>
      </div>

      {/* Right side - User Profile & Actions */}
      <div className="flex items-center gap-4">
        {/* Theme Toggle */}
        <Button
          variant="outline"
          size="icon"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          className="rounded-lg border-border hover:bg-accent hover:text-accent-foreground"
        >
          {theme === "dark" ? <Sun size={20} /> : <Moon size={20} />}
        </Button>

        {/* User Profile */}
        <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-muted">
          <div className="w-8 h-8 rounded-full bg-accent flex items-center justify-center">
            <User size={16} className="text-accent-foreground" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-medium text-foreground">User</span>
            <span className="text-xs text-muted-foreground">{userEmail}</span>
          </div>
        </div>

        {/* Logout Button */}
        <Button
          variant="outline"
          size="sm"
          onClick={onLogout}
          className="gap-2 border-border hover:bg-accent hover:text-accent-foreground bg-transparent"
        >
          <LogOut size={16} />
          Logout
        </Button>
      </div>
    </div>
  )
}
