// types.ts
export interface AuthConfig {
  clientId: string;
  authority: string;
  redirectUri: string;
  scopes?: string[];
  idleTimeoutMinutes?: number;
  warningTimeoutMinutes?: number;
  enableIdleDetection?: boolean;
  activityEvents?: string[];
}

export interface User {
  id: string;
  name: string;
  email: string;
  roles?: string[];
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  accessToken: string | null;
  idToken: string | null;
  error: string | null;
  sessionExpiry: number | null;
  isIdle: boolean;
  idleWarning: boolean;
  lastActivity: number;
}

export interface AuthActions {
  login: () => Promise<void>;
  logout: () => Promise<void>;
  loginRedirect: () => Promise<void>;
  acquireTokenSilent: (scopes?: string[]) => Promise<string | null>;
  acquireTokenPopup: (scopes?: string[]) => Promise<string | null>;
  handleRedirectPromise: () => Promise<void>;
  clearError: () => void;
  updateActivity: () => void;
  extendSession: () => void;
  resetIdleState: () => void;
}

export type AuthStore = AuthState & AuthActions;

// msalConfig.ts
import { Configuration, LogLevel } from '@azure/msal-browser';

export const createMsalConfig = (config: AuthConfig): Configuration => ({
  auth: {
    clientId: config.clientId,
    authority: config.authority,
    redirectUri: config.redirectUri,
    postLogoutRedirectUri: config.redirectUri,
  },
  cache: {
    cacheLocation: 'sessionStorage',
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        switch (level) {
          case LogLevel.Error:
            console.error(message);
            break;
          case LogLevel.Info:
            console.info(message);
            break;
          case LogLevel.Verbose:
            console.debug(message);
            break;
          case LogLevel.Warning:
            console.warn(message);
            break;
        }
      },
    },
    windowHashTimeout: 60000,
    iframeHashTimeout: 6000,
    loadFrameTimeout: 0,
  },
});

// idleDetection.ts
export class IdleDetection {
  private idleTimer: NodeJS.Timeout | null = null;
  private warningTimer: NodeJS.Timeout | null = null;
  private lastActivity: number = Date.now();
  private isIdle: boolean = false;
  private callbacks: {
    onIdle?: () => void;
    onWarning?: () => void;
    onActivity?: () => void;
  } = {};

  constructor(
    private idleTimeoutMs: number,
    private warningTimeoutMs: number,
    private activityEvents: string[] = [
      'mousedown',
      'mousemove',
      'keypress',
      'scroll',
      'touchstart',
      'click',
    ]
  ) {
    this.setupEventListeners();
    this.resetTimer();
  }

  private setupEventListeners(): void {
    this.activityEvents.forEach(event => {
      document.addEventListener(event, this.handleActivity, true);
    });
  }

  private handleActivity = (): void => {
    this.lastActivity = Date.now();
    
    if (this.isIdle) {
      this.isIdle = false;
      this.callbacks.onActivity?.();
    }

    this.resetTimer();
  };

  private resetTimer(): void {
    this.clearTimers();

    // Set warning timer
    this.warningTimer = setTimeout(() => {
      this.callbacks.onWarning?.();
    }, this.warningTimeoutMs);

    // Set idle timer
    this.idleTimer = setTimeout(() => {
      this.isIdle = true;
      this.callbacks.onIdle?.();
    }, this.idleTimeoutMs);
  }

  private clearTimers(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    if (this.warningTimer) {
      clearTimeout(this.warningTimer);
      this.warningTimer = null;
    }
  }

  public setCallbacks(callbacks: typeof this.callbacks): void {
    this.callbacks = { ...this.callbacks, ...callbacks };
  }

  public getLastActivity(): number {
    return this.lastActivity;
  }

  public isUserIdle(): boolean {
    return this.isIdle;
  }

  public reset(): void {
    this.isIdle = false;
    this.lastActivity = Date.now();
    this.resetTimer();
  }

  public destroy(): void {
    this.clearTimers();
    this.activityEvents.forEach(event => {
      document.removeEventListener(event, this.handleActivity, true);
    });
  }
}

// authStore.ts
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { 
  PublicClientApplication, 
  AccountInfo, 
  SilentRequest,
  PopupRequest,
  EndSessionRequest,
  AuthenticationResult
} from '@azure/msal-browser';
import { AuthStore, AuthConfig, User } from './types';
import { createMsalConfig } from './msalConfig';
import { IdleDetection } from './idleDetection';

const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

export const createAuthStore = (config: AuthConfig) => {
  const msalConfig = createMsalConfig(config);
  const msalInstance = new PublicClientApplication(msalConfig);
  
  let idleDetection: IdleDetection | null = null;

  const store = create<AuthStore>()(
    subscribeWithSelector((set, get) => ({
      // Initial state
      isAuthenticated: false,
      isLoading: true,
      user: null,
      accessToken: null,
      idToken: null,
      error: null,
      sessionExpiry: null,
      isIdle: false,
      idleWarning: false,
      lastActivity: Date.now(),

      // Actions
      login: async () => {
        try {
          set({ isLoading: true, error: null });
          
          const loginRequest: PopupRequest = {
            scopes: config.scopes || DEFAULT_SCOPES,
            prompt: 'select_account'
          };

          const response = await msalInstance.loginPopup(loginRequest);
          await handleAuthenticationResult(response);
          
        } catch (error) {
          console.error('Login failed:', error);
          set({ 
            error: error instanceof Error ? error.message : 'Login failed',
            isLoading: false 
          });
        }
      },

      loginRedirect: async () => {
        try {
          set({ isLoading: true, error: null });
          
          const loginRequest = {
            scopes: config.scopes || DEFAULT_SCOPES,
          };

          await msalInstance.loginRedirect(loginRequest);
        } catch (error) {
          console.error('Login redirect failed:', error);
          set({ 
            error: error instanceof Error ? error.message : 'Login redirect failed',
            isLoading: false 
          });
        }
      },

      logout: async () => {
        try {
          set({ isLoading: true });
          
          const account = msalInstance.getActiveAccount();
          const logoutRequest: EndSessionRequest = {
            account: account || undefined,
            postLogoutRedirectUri: config.redirectUri
          };

          // Clean up idle detection
          if (idleDetection) {
            idleDetection.destroy();
            idleDetection = null;
          }

          await msalInstance.logoutPopup(logoutRequest);
          
          set({
            isAuthenticated: false,
            isLoading: false,
            user: null,
            accessToken: null,
            idToken: null,
            error: null,
            sessionExpiry: null,
            isIdle: false,
            idleWarning: false,
            lastActivity: Date.now()
          });
          
        } catch (error) {
          console.error('Logout failed:', error);
          set({ 
            error: error instanceof Error ? error.message : 'Logout failed',
            isLoading: false 
          });
        }
      },

      acquireTokenSilent: async (scopes?: string[]) => {
        try {
          const account = msalInstance.getActiveAccount();
          if (!account) {
            throw new Error('No active account found');
          }

          const silentRequest: SilentRequest = {
            scopes: scopes || config.scopes || DEFAULT_SCOPES,
            account: account,
          };

          const response = await msalInstance.acquireTokenSilent(silentRequest);
          
          set({ 
            accessToken: response.accessToken,
            sessionExpiry: response.expiresOn ? response.expiresOn.getTime() : null
          });
          
          return response.accessToken;
        } catch (error) {
          console.error('Silent token acquisition failed:', error);
          return null;
        }
      },

      acquireTokenPopup: async (scopes?: string[]) => {
        try {
          const account = msalInstance.getActiveAccount();
          
          const popupRequest: PopupRequest = {
            scopes: scopes || config.scopes || DEFAULT_SCOPES,
            account: account || undefined,
          };

          const response = await msalInstance.acquireTokenPopup(popupRequest);
          
          set({ 
            accessToken: response.accessToken,
            sessionExpiry: response.expiresOn ? response.expiresOn.getTime() : null
          });
          
          return response.accessToken;
        } catch (error) {
          console.error('Popup token acquisition failed:', error);
          set({ error: error instanceof Error ? error.message : 'Token acquisition failed' });
          return null;
        }
      },

      handleRedirectPromise: async () => {
        try {
          set({ isLoading: true });
          const response = await msalInstance.handleRedirectPromise();
          
          if (response) {
            await handleAuthenticationResult(response);
          } else {
            // Check if user is already logged in
            const accounts = msalInstance.getAllAccounts();
            if (accounts.length > 0) {
              msalInstance.setActiveAccount(accounts[0]);
              await setUserFromAccount(accounts[0]);
              set({ isAuthenticated: true, isLoading: false });
              setupIdleDetection();
            } else {
              set({ isLoading: false });
            }
          }
        } catch (error) {
          console.error('Handle redirect failed:', error);
          set({ 
            error: error instanceof Error ? error.message : 'Authentication failed',
            isLoading: false 
          });
        }
      },

      clearError: () => {
        set({ error: null });
      },

      updateActivity: () => {
        set({ 
          lastActivity: Date.now(), 
          isIdle: false, 
          idleWarning: false 
        });
        if (idleDetection) {
          idleDetection.reset();
        }
      },

      extendSession: () => {
        const { acquireTokenSilent } = get();
        acquireTokenSilent();
        get().updateActivity();
      },

      resetIdleState: () => {
        set({ isIdle: false, idleWarning: false });
        if (idleDetection) {
          idleDetection.reset();
        }
      }
    }))
  );

  // Helper functions
  const handleAuthenticationResult = async (response: AuthenticationResult) => {
    const { account } = response;
    
    if (account) {
      msalInstance.setActiveAccount(account);
      await setUserFromAccount(account);
      
      set({
        isAuthenticated: true,
        isLoading: false,
        accessToken: response.accessToken,
        idToken: response.idToken,
        sessionExpiry: response.expiresOn ? response.expiresOn.getTime() : null,
        error: null
      });

      setupIdleDetection();
    }
  };

  const setUserFromAccount = async (account: AccountInfo) => {
    const user: User = {
      id: account.localAccountId,
      name: account.name || '',
      email: account.username || '',
      roles: account.idTokenClaims?.roles as string[] || []
    };
    
    set({ user });
  };

  const setupIdleDetection = () => {
    if (!config.enableIdleDetection || idleDetection) return;

    const idleTimeoutMs = (config.idleTimeoutMinutes || 30) * 60 * 1000;
    const warningTimeoutMs = (config.warningTimeoutMinutes || 25) * 60 * 1000;

    idleDetection = new IdleDetection(
      idleTimeoutMs,
      warningTimeoutMs,
      config.activityEvents
    );

    idleDetection.setCallbacks({
      onWarning: () => {
        store.setState({ idleWarning: true });
      },
      onIdle: () => {
        store.setState({ isIdle: true, idleWarning: false });
        // Auto logout after idle timeout
        setTimeout(() => {
          const state = store.getState();
          if (state.isIdle && state.isAuthenticated) {
            state.logout();
          }
        }, 2 * 60 * 1000); // 2 minutes grace period
      },
      onActivity: () => {
        store.setState({ 
          isIdle: false, 
          idleWarning: false, 
          lastActivity: Date.now() 
        });
      }
    });
  };

  // Initialize MSAL
  msalInstance.initialize().then(() => {
    store.getState().handleRedirectPromise();
  });

  return store;
};

// main.ts - Main export
export { createAuthStore } from './authStore';
export { IdleDetection } from './idleDetection';
export * from './types';

// Usage example:
/*
import { createAuthStore } from './msal-auth-library';

const useAuth = createAuthStore({
  clientId: 'your-client-id',
  authority: 'https://login.microsoftonline.com/your-tenant-id',
  redirectUri: 'http://localhost:3000',
  scopes: ['User.Read'],
  idleTimeoutMinutes: 30,
  warningTimeoutMinutes: 25,
  enableIdleDetection: true,
  activityEvents: ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart']
});

// In your React component:
const { 
  isAuthenticated, 
  isLoading, 
  user, 
  login, 
  logout, 
  isIdle, 
  idleWarning,
  extendSession 
} = useAuth();

// In vanilla JS:
const authStore = useAuth.getState();
authStore.login();
*/

// package.json dependencies:
/*
{
  "dependencies": {
    "@azure/msal-browser": "^4.15.0",
    "zustand": "^4.4.1"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0"
  }
}
*/
