import { useState } from "react";
import { X, Lock, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface SecurityModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (password: string) => void;
  isLoading?: boolean;
}

export function SecurityModal({ isOpen, onClose, onSubmit, isLoading = false }: SecurityModalProps) {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(password);
  };

  const handleClose = () => {
    setPassword("");
    setShowPassword(false);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-in fade-in-0 duration-300">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in-0 duration-300"
        onClick={handleClose}
      />
      
      {/* Modal */}
      <Card className="relative w-full max-w-md bg-card border shadow-2xl animate-in zoom-in-95 slide-in-from-bottom-2 duration-300">
        <CardHeader className="relative pb-4">
          <Button
            variant="ghost"
            size="sm"
            className="absolute right-2 top-2 h-8 w-8 p-0 hover:bg-destructive/10 hover:text-destructive"
            onClick={handleClose}
          >
            <X className="h-4 w-4" />
          </Button>
          <CardTitle className="text-center text-lg font-semibold text-foreground flex items-center justify-center gap-2">
            <Lock className="h-5 w-5 text-amber-500" />
            Password Keamanan
          </CardTitle>
        </CardHeader>
        
        <CardContent>
          <div className="space-y-4">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">
                Masukkan password keamanan untuk menambahkan nomor baru
              </p>
            </div>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="relative">
                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="Masukkan password keamanan"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pr-10 h-12 text-center"
                  required
                  autoFocus
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-12 w-12 p-0"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>
              
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleClose}
                  className="flex-1"
                  disabled={isLoading}
                >
                  Batal
                </Button>
                <Button
                  type="submit"
                  className="flex-1 bg-green-600 hover:bg-green-700"
                  disabled={isLoading || !password}
                >
                  {isLoading ? "Memverifikasi..." : "Verifikasi"}
                </Button>
              </div>
            </form>
            
            <div className="text-xs text-center text-muted-foreground border-t pt-3">
              Password ini diperlukan untuk keamanan tambahan saat menambah nomor
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}