/**
 * Vulnerable Admin Module
 * Contains A01 - Broken Access Control
 */
export declare function deleteUser(userId: string, requestorId: string): Promise<{
    success: boolean;
    message: string;
}>;
export declare function getUserData(userId: string, requestorId: string): Promise<any>;
export declare function updateUser(userId: string, updates: any): Promise<{
    success: boolean;
}>;
export declare function readUserFile(userId: string, filename: string): Promise<{
    success: boolean;
    content: any;
    error?: undefined;
} | {
    success: boolean;
    error: any;
    content?: undefined;
}>;
//# sourceMappingURL=admin.d.ts.map