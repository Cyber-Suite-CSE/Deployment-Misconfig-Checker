"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Slider } from "@/components/ui/slider"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Rocket, Monitor, History, Upload, Code } from "lucide-react"
import { ScanResults } from "./scan-results"

interface ScanConfig {
  domain: string
  modules: string[]
  verbose: boolean
  enumTechniques: string[]
  scanMode: string
  customPorts: string
  activeThreads: number
  cdnBypass: boolean
  deepCrawl: boolean
  disableAI: boolean
  wordlistFile?: File
}

const MOCK_SCAN_DATA = {
  enabled_modules: ["domain_enumeration", "service_discovery", "web_analysis"],
  execution_time: 9.0459,
  modules: {
    domain_enumeration: {
      all_subdomains: [
        "access.uom.lk",
        "ad.uom.lk",
        "alumni.uom.lk",
        "av.uom.lk",
        "bbb.uom.lk",
        "black.uom.lk",
        "book.uom.lk",
        "booking.uom.lk",
        "cache.uom.lk",
        "cache2.uom.lk",
      ],
      domain: "online.uom.lk",
      modules: {
        active: {
          subdomains: [
            "chat.uom.lk",
            "ps.uom.lk",
            "webhosting.uom.lk",
            "ns.uom.lk",
            "fw1.uom.lk",
            "gp.uom.lk",
            "wiki.uom.lk",
            "wlan.uom.lk",
            "tp.uom.lk",
            "connect.uom.lk",
          ],
          statistics: {
            total_subdomains: 98,
            success_rate: 0,
            total_duration: 3.4081737995147705,
          },
        },
        dns: {
          dns_records: {
            A: ["192.248.8.68", "192.248.8.87"],
            AAAA: ["2401:dd00:10:1::68", "2401:dd00:10:1::87"],
            MX: ["inrelay-a.uom.lk"],
            NS: ["ns-c.nic.lk", "ns.mrt.ac.lk", "ns-t.nic.lk"],
          },
          statistics: {
            total_records: 12,
            total_duration: 0.11480522155761719,
          },
        },
        fingerprinting: {
          summary: {
            unique_technologies: [
              "Moodle",
              "PHP",
              "OpenSSL",
              "Apache",
              "MathJax",
              "RequireJS",
              "jsDelivr",
              "Font Awesome",
              "Google Services",
              "Google Font API",
              "CDN",
            ],
            common_issues: [
              "X-Content-Type-Options",
              "Referrer-Policy",
              "Permissions-Policy",
              "X-XSS-Protection",
              "Content-Security-Policy",
              "X-Frame-Options",
              "Strict-Transport-Security",
            ],
            security_score_avg: 0.0,
          },
        },
        passive: {
          statistics: {
            certificates_analyzed: 1,
            ct_logs_processed: 76,
            total_subdomains: 2,
          },
          subdomains: ["vpl.online.uom.lk", "online.uom.lk"],
        },
      },
      statistics: {
        total_subdomains: 84,
        technologies_detected: 11,
        security_issues_found: 7,
      },
    },
    service_discovery: {
      service_results: {
        services: {
          "22": {
            port: 22,
            service: "SSH",
            version: "2.0",
            ssl: false,
          },
          "80": {
            port: 80,
            service: "HTTP",
            version: "2.4.62",
            ssl: false,
          },
          "443": {
            port: 443,
            service: "HTTPS",
            version: "2.4.62",
            ssl: true,
          },
        },
        summary: {
          total_services: 3,
          ssl_services: ["HTTPS (port 443)"],
        },
      },
    },
    web_analysis: {
      web_crawl: {
        apis: [
          "http://online.uom.lk/login/forgot_password.php",
          "http://online.uom.lk/login/index.php",
          "https://online.uom.lk/login/index.php",
          "https://online.uom.lk/login/forgot_password.php",
          "https://online.uom.lk/admin/tool/dataprivacy/summary.php",
          "http://online.uom.lk/admin/tool/dataprivacy/summary.php",
        ],
      },
      cdn_detection: {
        cdn_detected: true,
        cdn_name: "Google CDN",
      },
    },
  },
  summary: {
    apis_discovered: 6,
    cdn_detected: true,
    total_open_ports: 3,
    total_subdomains: 84,
    technologies_detected: 11,
  },
  target_domain: "online.uom.lk",
}

export function WebDomainScanner({ domain }: { domain: string }) {
  const [activeTab, setActiveTab] = useState("new-scan")
  const [wordlistFile, setWordlistFile] = useState<File | null>(null)
  const [showMockData, setShowMockData] = useState(false)
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    domain: domain || "",
    modules: ["domain_enumeration", "service_discovery", "web_analysis"],
    verbose: true,
    enumTechniques: ["passive", "active", "dns", "fingerprinting"],
    scanMode: "smart",
    customPorts: "",
    activeThreads: 10,
    cdnBypass: true,
    deepCrawl: false,
    disableAI: false,
  })

  if (showMockData) {
    return <ScanResults data={MOCK_SCAN_DATA} onBack={() => setShowMockData(false)} />
  }

  return (
    <div className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="new-scan" className="gap-2">
            <Rocket size={16} />
            New Scan
          </TabsTrigger>
          <TabsTrigger value="monitor" className="gap-2">
            <Monitor size={16} />
            Monitor Jobs
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-2">
            <History size={16} />
            Job History
          </TabsTrigger>
        </TabsList>

        {/* New Scan Tab */}
        <TabsContent value="new-scan" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Basic Settings */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-accent">⚙️</span>
                  Basic Settings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Select Modules to Run</label>
                  <div className="space-y-2">
                    {["domain_enumeration", "service_discovery", "web_analysis"].map((module) => (
                      <div key={module} className="flex items-center gap-2">
                        <Checkbox
                          checked={scanConfig.modules.includes(module)}
                          onCheckedChange={(checked) => {
                            setScanConfig((prev) => ({
                              ...prev,
                              modules: checked ? [...prev.modules, module] : prev.modules.filter((m) => m !== module),
                            }))
                          }}
                          id={module}
                        />
                        <label htmlFor={module} className="text-sm cursor-pointer">
                          {module.replace("_", " ").toUpperCase()}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Verbose Output</label>
                  <Checkbox
                    checked={scanConfig.verbose}
                    onCheckedChange={(checked) => {
                      setScanConfig((prev) => ({ ...prev, verbose: !!checked }))
                    }}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Domain Enumeration */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-accent">🔍</span>
                  Domain Enumeration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Enumeration Techniques</label>
                  <div className="space-y-2">
                    {["passive", "active", "dns", "fingerprinting"].map((tech) => (
                      <div key={tech} className="flex items-center gap-2">
                        <Checkbox
                          checked={scanConfig.enumTechniques.includes(tech)}
                          onCheckedChange={(checked) => {
                            setScanConfig((prev) => ({
                              ...prev,
                              enumTechniques: checked
                                ? [...prev.enumTechniques, tech]
                                : prev.enumTechniques.filter((t) => t !== tech),
                            }))
                          }}
                          id={tech}
                        />
                        <label htmlFor={tech} className="text-sm cursor-pointer capitalize">
                          {tech}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Service Discovery */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <span className="text-accent">🎯</span>
                Service Discovery
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Port Scan Mode</label>
                  <Select
                    value={scanConfig.scanMode}
                    onValueChange={(value) => {
                      setScanConfig((prev) => ({ ...prev, scanMode: value }))
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="quick">Quick (Top 100)</SelectItem>
                      <SelectItem value="smart">Smart (Top 1000)</SelectItem>
                      <SelectItem value="deep">Deep (All 65535)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">Custom Ports (Optional)</label>
                  <input
                    type="text"
                    placeholder="80,443,8080"
                    value={scanConfig.customPorts}
                    onChange={(e) => {
                      setScanConfig((prev) => ({ ...prev, customPorts: e.target.value }))
                    }}
                    className="w-full px-3 py-2 rounded-lg border border-border bg-input text-foreground"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Advanced Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <span className="text-accent">⚡</span>
                Advanced Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="text-sm font-medium mb-3 block">Active Threads: {scanConfig.activeThreads}</label>
                  <Slider
                    value={[scanConfig.activeThreads]}
                    onValueChange={(value) => {
                      setScanConfig((prev) => ({ ...prev, activeThreads: value[0] }))
                    }}
                    min={1}
                    max={50}
                    step={1}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={scanConfig.cdnBypass}
                    onCheckedChange={(checked) => {
                      setScanConfig((prev) => ({ ...prev, cdnBypass: !!checked }))
                    }}
                    id="cdn-bypass"
                  />
                  <label htmlFor="cdn-bypass" className="text-sm cursor-pointer">
                    CDN Bypass
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={scanConfig.deepCrawl}
                    onCheckedChange={(checked) => {
                      setScanConfig((prev) => ({ ...prev, deepCrawl: !!checked }))
                    }}
                    id="deep-crawl"
                  />
                  <label htmlFor="deep-crawl" className="text-sm cursor-pointer">
                    Deep Crawl
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={scanConfig.disableAI}
                    onCheckedChange={(checked) => {
                      setScanConfig((prev) => ({ ...prev, disableAI: !!checked }))
                    }}
                    id="disable-ai"
                  />
                  <label htmlFor="disable-ai" className="text-sm cursor-pointer">
                    Disable AI
                  </label>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <span className="text-accent">📄</span>
                Custom Wordlist (Optional)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-6 text-center hover:border-accent transition-colors cursor-pointer">
                <input
                  type="file"
                  accept=".txt"
                  onChange={(e) => {
                    if (e.target.files?.[0]) {
                      setWordlistFile(e.target.files[0])
                    }
                  }}
                  className="hidden"
                  id="wordlist-upload"
                />
                <label htmlFor="wordlist-upload" className="cursor-pointer block">
                  <Upload size={24} className="mx-auto mb-2 text-accent" />
                  <p className="text-sm font-medium">
                    {wordlistFile ? wordlistFile.name : "Drag and drop or click to upload wordlist"}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">Limit 200MB per file • TXT format</p>
                </label>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Monitor Jobs Tab */}
        <TabsContent value="monitor" className="space-y-6">
          <div className="flex justify-end mb-4">
            <Button
              onClick={() => setShowMockData(true)}
              variant="outline"
              className="gap-2 border-border hover:bg-accent hover:text-accent-foreground"
            >
              <Code size={20} />
              Dev Mock Data
            </Button>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Active Jobs</CardTitle>
              <CardDescription>Monitor running scans in real-time</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12 text-muted-foreground">
                <p>No active jobs. Start a new scan to begin monitoring.</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Job History Tab */}
        <TabsContent value="history" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Scan History</CardTitle>
              <CardDescription>View past scan results and statistics</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12 text-muted-foreground">
                <p>No scan history available yet.</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
