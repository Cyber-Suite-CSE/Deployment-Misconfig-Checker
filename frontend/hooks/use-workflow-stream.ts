"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"

export type WorkflowEvent =
  | {
      type: string
      message: string
      payload?: Record<string, unknown>
      metadata?: Record<string, unknown> | null
      timestamp: number
    }

interface UseWorkflowStreamOptions {
  apiUrl?: string
}

interface UseWorkflowStreamState {
  events: WorkflowEvent[]
  isStreaming: boolean
  error: string | null
  startStream: (prompt: string, metadata?: Record<string, unknown>) => void
  reset: () => void
}

const defaultApiUrl = process.env.NEXT_PUBLIC_AGENT_API_URL || "http://localhost:8000"

export function useWorkflowStream(options?: UseWorkflowStreamOptions): UseWorkflowStreamState {
  const { apiUrl = defaultApiUrl } = options ?? {}
  const [events, setEvents] = useState<WorkflowEvent[]>([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortControllerRef = useRef<AbortController | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  const reset = useCallback(() => {
    abortControllerRef.current?.abort()
    eventSourceRef.current?.close()
    abortControllerRef.current = null
    eventSourceRef.current = null
    setEvents([])
    setError(null)
    setIsStreaming(false)
  }, [])

  useEffect(() => {
    return () => {
      reset()
    }
  }, [reset])

  const startStream = useCallback(
    async (prompt: string, metadata?: Record<string, unknown>) => {
      reset()
      const controller = new AbortController()
      abortControllerRef.current = controller

      try {
        setIsStreaming(true)
        setError(null)

        const response = await fetch(`${apiUrl}/workflows/run`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "text/event-stream",
          },
          body: JSON.stringify({
            prompt,
            metadata: metadata ?? null,
          }),
          mode: "cors",
          signal: controller.signal,
        })

        console.log("[WorkflowStream] response status:", response.status, response.statusText)

        if (!response.ok || !response.body) {
          throw new Error(`Streaming request failed: ${response.status}`)
        }

        const reader = response.body.getReader()
        const decoder = new TextDecoder("utf-8")
        let partialChunk = ""

        // Process stream chunks iteratively to avoid stack overflow
        while (true) {
          // console.log("Testing stream read...")
          const { done, value } = await reader.read()
          if (done) {
            setIsStreaming(false)
            break
          }

          const decodedData = decoder.decode(value, { stream: true })
          partialChunk += decodedData
          // console.log(decodedData)
          const lines = partialChunk.split("\n")
          partialChunk = lines.pop() || ""
          console.log("[WorkflowStream] received chunk lines:", lines)
          lines.forEach((line) => {
            const trimmed = line.trim()
            if (!trimmed.startsWith("data:")) {
              return
            }

            try {
              const json = trimmed.replace(/^data:\s*/, "")
              console.log("[WorkflowStream] raw event:", json)
              const parsed = JSON.parse(json) as Omit<WorkflowEvent, "timestamp">
              console.log("[WorkflowStream] parsed event:", parsed)
              setEvents((prev) => [...prev, { ...parsed, timestamp: Date.now() }])
            } catch (err) {
              console.error("Failed to parse SSE payload:", err, trimmed)
            }
          })
        }
      } catch (err) {
        if ((err as DOMException).name === "AbortError") {
          return
        }

        console.error("Workflow stream error:", err)
        console.error("[WorkflowStream] Fetch failed with prompt:", prompt)
        setError((err as Error).message ?? "Streaming error")
        setIsStreaming(false)
      }
    },
    [apiUrl, reset]
  )

  return useMemo(
    () => ({
      events,
      isStreaming,
      error,
      startStream,
      reset,
    }),
    [events, isStreaming, error, startStream, reset]
  )
}
