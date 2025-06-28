import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Database, Eye, EyeOff, Lock, User, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { loginSchema, type LoginRequest } from "@shared/schema";
import { authApi } from "@/lib/auth";
import { useToast } from "@/hooks/use-toast";
import { brandingConfig } from "@/config/branding";

export default function Login() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showPassword, setShowPassword] = useState(false);

  // Check if user is already authenticated
  const { data: auth, isLoading: authLoading } = useQuery({
    queryKey: ["/api/auth/me"],
    queryFn: () => authApi.getMe(),
    retry: false,
    refetchOnWindowFocus: false,
  });

  // Redirect to dashboard if already authenticated
  useEffect(() => {
    if (!authLoading && auth?.isAuthenticated) {
      setLocation("/dashboard");
    }
  }, [auth?.isAuthenticated, authLoading, setLocation]);

  const form = useForm<LoginRequest>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  const loginMutation = useMutation({
    mutationFn: (data: LoginRequest) => authApi.login(data.username, data.password),
    onSuccess: () => {
      // Invalidate auth cache to refresh user data
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      toast({
        title: "Login Successful", 
        description: "Welcome to the database management system",
      });
      // Navigate to dashboard with proper delay for smooth transition
      setTimeout(() => {
        setLocation("/dashboard");
      }, 500);
    },
    onError: (error: any) => {
      toast({
        title: "Login Failed",
        description: error.message || "Invalid username or password",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: LoginRequest) => {
    loginMutation.mutate(data);
  };

  // Show loading state while checking authentication
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Don't render login form if already authenticated (will redirect)
  if (auth?.isAuthenticated) {
    return null;
  }

  return (
    <div 
      className="min-h-screen flex items-center justify-center px-4 relative animate-in fade-in-0 duration-500"
      style={{
        backgroundImage: `url('${brandingConfig.wallpaper.url}')`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat'
      }}
    >
      {/* Overlay for better readability */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm"></div>
      
      <div className="max-w-md w-full relative z-10 animate-in slide-in-from-bottom duration-700 delay-200">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full mb-4 animate-in zoom-in-50 duration-500 delay-400 hover:scale-110 transition-transform overflow-hidden border-2 border-white/20 backdrop-blur-md bg-white/10">
            <img 
              src={brandingConfig.logo.url}
              alt={brandingConfig.logo.alt}
              className="w-full h-full object-cover"
              onError={(e) => {
                // Fallback to Database icon if image fails to load
                const target = e.target as HTMLImageElement;
                target.style.display = 'none';
                const parent = target.parentElement;
                if (parent) {
                  parent.innerHTML = '<Database class="h-8 w-8 text-white" />';
                  parent.className = parent.className.replace('overflow-hidden', '') + ' bg-primary';
                }
              }}
            />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2 animate-in slide-in-from-top duration-500 delay-600 drop-shadow-lg">{brandingConfig.title}</h1>
          <p className="text-white/80 animate-in fade-in-50 duration-500 delay-700 drop-shadow-md">{brandingConfig.subtitle}</p>
        </div>

        {/* Login Form */}
        <Card className="shadow-2xl animate-in slide-in-from-bottom duration-500 delay-800 hover:shadow-xl transition-all backdrop-blur-md bg-white/95 dark:bg-gray-900/95 border-white/20">
          <CardContent className="p-8">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem className="animate-in slide-in-from-left duration-500 delay-900">
                      <FormLabel className="flex items-center gap-2">
                        <User className="h-4 w-4" />
                        Username
                      </FormLabel>
                      <FormControl>
                        <Input
                          placeholder="Enter your username"
                          {...field}
                          className="h-12 transition-all duration-200 focus:scale-[1.02] focus:border-primary"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem className="animate-in slide-in-from-right duration-500 delay-1000">
                      <FormLabel className="flex items-center gap-2">
                        <Lock className="h-4 w-4" />
                        Password
                      </FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showPassword ? "text" : "password"}
                            placeholder="Enter your password"
                            {...field}
                            className="h-12 pr-12 transition-all duration-200 focus:scale-[1.02] focus:border-primary"
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent transition-all duration-200 hover:scale-110"
                            onClick={() => setShowPassword(!showPassword)}
                          >
                            {showPassword ? (
                              <EyeOff className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <Eye className="h-4 w-4 text-muted-foreground" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <Button
                  type="submit"
                  className="w-full h-12 animate-in slide-in-from-bottom duration-500 delay-1100 transition-all duration-200 hover:scale-105 active:scale-95"
                  disabled={loginMutation.isPending}
                >
                  {loginMutation.isPending ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Signing in...
                    </div>
                  ) : (
                    <>
                      <User className="mr-2 h-4 w-4" />
                      Sign In
                    </>
                  )}
                </Button>
              </form>
            </Form>

            {/* Security Notice */}
            <div className="mt-6 p-4 bg-white/10 backdrop-blur-sm rounded-lg animate-in fade-in-50 duration-500 delay-1200 border border-white/20">
              <div className="flex items-start">
                <Shield className="h-5 w-5 text-primary mt-0.5 mr-3" />
                <div className="text-sm text-gray-700 dark:text-gray-300">
                  <p className="font-medium mb-1 text-gray-900 dark:text-white">MILLICENT BLUENIGHT</p>
                  <p>All data is stored securely outside the public directory. Session timeout occurs after 30 minutes of inactivity.</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
