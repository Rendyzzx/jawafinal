import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { authApi } from "@/lib/auth";
import { useEffect } from "react";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const [, setLocation] = useLocation();
  
  const { data: auth, isLoading, isError } = useQuery({
    queryKey: ["/api/auth/me"],
    queryFn: () => authApi.getMe(),
    retry: false,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (!isLoading && (!auth?.isAuthenticated || isError)) {
      setLocation("/");
    }
  }, [auth?.isAuthenticated, isLoading, isError, setLocation]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!auth?.isAuthenticated || isError) {
    return null;
  }

  return <>{children}</>;
}