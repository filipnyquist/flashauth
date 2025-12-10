/**
 * FlashAuth Permission Utilities
 * Permission matching and role-to-permission mapping
 */

/**
 * Role to permissions mapping
 */
export type RolePermissions = Record<string, string[]>;

/**
 * Match a permission against a pattern
 * Supports wildcard matching with '*'
 */
export function matchPermission(permission: string, pattern: string): boolean {
  // Exact match
  if (pattern === permission) {
    return true;
  }

  // Super admin wildcard
  if (pattern === '*') {
    return true;
  }

  // Wildcard matching: "users:*" matches "users:read", "users:write", etc.
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -2);
    return permission.startsWith(prefix + ':');
  }

  return false;
}

/**
 * Check if a list of permissions includes a specific permission
 * Supports wildcard matching
 */
export function hasPermission(permissions: string[], permission: string): boolean {
  return permissions.some(perm => matchPermission(permission, perm));
}

/**
 * Check if a list of permissions includes any of the specified permissions
 */
export function hasAnyPermission(permissions: string[], required: string[]): boolean {
  return required.some(perm => hasPermission(permissions, perm));
}

/**
 * Check if a list of permissions includes all of the specified permissions
 */
export function hasAllPermissions(permissions: string[], required: string[]): boolean {
  return required.every(perm => hasPermission(permissions, perm));
}

/**
 * Expand roles to permissions based on role-permission mapping
 */
export function expandRolesToPermissions(
  roles: string[],
  rolePermissions: RolePermissions
): string[] {
  const permissions = new Set<string>();

  for (const role of roles) {
    const rolePerms = rolePermissions[role];
    if (rolePerms) {
      for (const perm of rolePerms) {
        permissions.add(perm);
      }
    }
  }

  return Array.from(permissions);
}

/**
 * Merge explicit permissions with role-based permissions
 */
export function mergePermissions(
  roles: string[],
  explicitPermissions: string[],
  rolePermissions: RolePermissions
): string[] {
  const rolePerms = expandRolesToPermissions(roles, rolePermissions);
  const allPermissions = new Set([...rolePerms, ...explicitPermissions]);
  return Array.from(allPermissions);
}

/**
 * Validate permission format
 * Permissions should be in format: "resource:action" or "*"
 */
export function validatePermissionFormat(permission: string): boolean {
  if (permission === '*') {
    return true;
  }

  // Check for wildcard format: "resource:*"
  if (permission.endsWith(':*')) {
    const resource = permission.slice(0, -2);
    return resource.length > 0 && /^[a-z][a-z0-9_-]*$/i.test(resource);
  }

  // Check for standard format: "resource:action"
  const parts = permission.split(':');
  if (parts.length !== 2) {
    return false;
  }

  const [resource, action] = parts;
  return (
    resource !== undefined &&
    action !== undefined &&
    resource.length > 0 &&
    action.length > 0 &&
    /^[a-z][a-z0-9_-]*$/i.test(resource) &&
    /^[a-z][a-z0-9_-]*$/i.test(action)
  );
}
