package com.yash.user.service;

import com.yash.user.model.Role;
import com.yash.user.model.RoleName;

import java.util.List;
import java.util.Optional;

public interface RoleService {
    Optional<Role> findByName(RoleName name);

    boolean assignRole(Long id, String roleName);

    boolean revokeRole(Long id, String roleName);

    List<String> getUserRoles(Long id);
}
