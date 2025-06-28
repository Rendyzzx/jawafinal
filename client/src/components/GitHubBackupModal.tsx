
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Github, Settings, Upload, FileText, Database } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

interface GitHubBackupModalProps {
  children: React.ReactNode;
}

export function GitHubBackupModal({ children }: GitHubBackupModalProps) {
  const [open, setOpen] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [realtimeEnabled, setRealtimeEnabled] = useState(true);
  const queryClient = useQueryClient();

  const configureMutation = useMutation({
    mutationFn: async (data: { repoUrl: string; realtime: boolean }) => {
      await apiRequest("POST", "/api/github-backup/configure", data);
    },
    onSuccess: () => {
      setOpen(false);
      setRepoUrl("");
    },
  });

  const triggerBackupMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/github-backup/trigger", {});
    },
  });

  const projectBackupMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/github-backup/project", {});
    },
  });

  const handleConfigure = (e: React.FormEvent) => {
    e.preventDefault();
    if (repoUrl.trim()) {
      configureMutation.mutate({ repoUrl: repoUrl.trim(), realtime: realtimeEnabled });
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {children}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Github className="h-5 w-5" />
            GitHub Backup Configuration
          </DialogTitle>
        </DialogHeader>
        
        <div className="space-y-6">
          <form onSubmit={handleConfigure} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="repoUrl">Repository URL</Label>
              <Input
                id="repoUrl"
                type="url"
                placeholder="https://username:token@github.com/username/repo.git"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                required
              />
              <p className="text-xs text-muted-foreground">
                Format: https://username:personal_access_token@github.com/username/repository.git
              </p>
            </div>

            <div className="flex items-center justify-between space-x-2">
              <div className="space-y-1">
                <Label htmlFor="realtime">Real-time Backup</Label>
                <p className="text-xs text-muted-foreground">
                  Automatically backup all file changes
                </p>
              </div>
              <Switch
                id="realtime"
                checked={realtimeEnabled}
                onCheckedChange={setRealtimeEnabled}
              />
            </div>
            
            <Button 
              type="submit" 
              className="w-full"
              disabled={configureMutation.isPending || !repoUrl.trim()}
            >
              <Settings className="h-4 w-4 mr-2" />
              {configureMutation.isPending ? "Configuring..." : "Configure Backup"}
            </Button>
          </form>

          <div className="border-t pt-4 space-y-3">
            <Button
              variant="outline"
              className="w-full"
              onClick={() => projectBackupMutation.mutate()}
              disabled={projectBackupMutation.isPending}
            >
              <FileText className="h-4 w-4 mr-2" />
              {projectBackupMutation.isPending ? "Backing up..." : "Backup Entire Project"}
            </Button>

            <Button
              variant="outline"
              className="w-full"
              onClick={() => triggerBackupMutation.mutate()}
              disabled={triggerBackupMutation.isPending}
            >
              <Database className="h-4 w-4 mr-2" />
              {triggerBackupMutation.isPending ? "Backing up..." : "Backup Database Only"}
            </Button>
          </div>

          {(configureMutation.isSuccess || triggerBackupMutation.isSuccess || projectBackupMutation.isSuccess) && (
            <div className="text-sm text-green-600 dark:text-green-400">
              {configureMutation.isSuccess && "GitHub backup configured successfully!"}
              {triggerBackupMutation.isSuccess && "Database backup completed successfully!"}
              {projectBackupMutation.isSuccess && "Project backup completed successfully!"}
            </div>
          )}

          {(configureMutation.error || triggerBackupMutation.error || projectBackupMutation.error) && (
            <div className="text-sm text-red-600 dark:text-red-400">
              {configureMutation.error?.message || triggerBackupMutation.error?.message || projectBackupMutation.error?.message}
            </div>
          )}

          <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg">
            <p className="text-xs text-blue-700 dark:text-blue-300">
              <strong>Real-time Backup:</strong> Semua perubahan file akan otomatis di-backup ke GitHub dalam 5 detik setelah perubahan terdeteksi.
            </p>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
