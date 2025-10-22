"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { SettingsIcon } from "lucide-react"

export function Settings() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Settings</h1>
        <p className="text-muted-foreground">Configure your security suite preferences</p>
      </div>

      {/* General Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SettingsIcon size={20} className="text-accent" />
            General Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Checkbox defaultChecked id="notifications" />
              <label htmlFor="notifications" className="text-sm cursor-pointer">
                Enable scan notifications
              </label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox defaultChecked id="auto-save" />
              <label htmlFor="auto-save" className="text-sm cursor-pointer">
                Auto-save scan results
              </label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="verbose-logs" />
              <label htmlFor="verbose-logs" className="text-sm cursor-pointer">
                Enable verbose logging
              </label>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* API Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>API Configuration</CardTitle>
          <CardDescription>Configure external API integrations</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium mb-2 block">API Key</label>
            <input
              type="password"
              placeholder="Enter your API key"
              className="w-full px-3 py-2 rounded-lg border border-border bg-input text-foreground"
            />
          </div>
          <div>
            <label className="text-sm font-medium mb-2 block">API Endpoint</label>
            <input
              type="text"
              placeholder="https://api.example.com"
              className="w-full px-3 py-2 rounded-lg border border-border bg-input text-foreground"
            />
          </div>
          <Button className="w-full bg-accent hover:bg-accent/90 text-accent-foreground">Save Configuration</Button>
        </CardContent>
      </Card>

      {/* Data Management */}
      <Card>
        <CardHeader>
          <CardTitle>Data Management</CardTitle>
          <CardDescription>Manage your scan data and exports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button variant="outline" className="w-full bg-transparent">
            Export All Scans
          </Button>
          <Button variant="outline" className="w-full bg-transparent">
            Clear Cache
          </Button>
          <Button variant="destructive" className="w-full">
            Delete All Data
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
