/**
 * Vulnerable Authentication Module
 * Contains A07 - Authentication Failures
 */
export declare function hashPassword(password: string): Promise<string>;
export declare function comparePasswords(input: string, stored: string): Promise<boolean>;
export declare function attemptLogin(username: string, password: string): Promise<{
    success: boolean;
    sessionId: string;
    user: any;
} | {
    success: boolean;
    sessionId?: undefined;
    user?: undefined;
}>;
export declare function createUser(username: string, email: string, password: string): Promise<{
    success: boolean;
}>;
//# sourceMappingURL=auth.d.ts.map