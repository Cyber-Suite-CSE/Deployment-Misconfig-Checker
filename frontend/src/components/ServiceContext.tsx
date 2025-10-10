'use client';

import { createContext, useContext, useState, ReactNode } from 'react';

type ServiceType = 'misconfig' | 'cve' | 'agent';

interface ServiceContextType {
  activeService: ServiceType;
  setActiveService: (service: ServiceType) => void;
}

const ServiceContext = createContext<ServiceContextType | undefined>(undefined);

export function ServiceProvider({ children }: { children: ReactNode }) {
  const [activeService, setActiveService] = useState<ServiceType>('misconfig');

  return (
    <ServiceContext.Provider value={{ activeService, setActiveService }}>
      {children}
    </ServiceContext.Provider>
  );
}

export function useService() {
  const context = useContext(ServiceContext);

  // Always create a fallback state so hook order remains stable
  const [fallbackActiveService, fallbackSetActiveService] = useState<ServiceType>('misconfig');

  if (context === undefined) {
    return {
      activeService: fallbackActiveService,
      setActiveService: fallbackSetActiveService,
    } as ServiceContextType;
  }

  return context;
}