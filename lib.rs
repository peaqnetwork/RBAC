#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod rbac {
    use ink_prelude::vec::Vec;
    use ink_storage::{
        traits::{
            PackedLayout,
            SpreadAllocate,
            SpreadLayout,
        },
        Mapping,
    };
    use ink_prelude::collections::BTreeSet;

    type DIDType = [u8; 32];

    type GroupDID = DIDType;
    type UserDID = DIDType;
    type UserGroupDID = DIDType;
    type RoleDID = DIDType;
    type PermissionDID = DIDType;
 

    #[derive(
        scale::Encode, scale::Decode, Clone, SpreadLayout,
        PackedLayout, Default, Ord, PartialOrd, Eq, PartialEq)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct UserGroupEntity {
        id: UserGroupDID,
        // Currently, we don't use is_group. Because groups cannot have the other groups now.
        is_group: bool,
    }


    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout, Default, PartialEq, Eq)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Role {
        id: RoleDID,
    }


    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout, Default, PartialEq, Eq)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Permission {
        id: PermissionDID,
    }

   
    #[ink(storage)]
    #[derive(SpreadAllocate, Default)]
    pub struct RBAC {
        // Note: UserDID is not the same as GroupDID. (Limitation)

        // map_group_has: key - GroupDID, value- Vec<UserGroupEntity>
        // For example:
        // GroupDID has UserDID1, UserDID2

        // However, currently, only the type of user can add into the group,
        // but the type of group cannot add into the group.
        // Therefore, all UserGroupEntities are user and we don't support the below example,
        // GroupDID has GroupDID2
        map_group_has: Mapping<GroupDID, Vec<UserGroupEntity>>,

        // map_user_group_entity_belong : key - UserGroupEntity, value- Vec<GroupDID>
        // This map is to let us find roles easily

        // Example:
        // > GroupDID has UserDID1
        // > GroupDID3 has UserDID1
        // UserDID1 belongs to GroupDID, GroupDID3
        map_user_group_entity_belong: Mapping<UserGroupEntity, Vec<GroupDID>>,

        // map_user_group_to_role : key - GroupDID/UserDID, value- Vec<Role>
        map_user_group_to_role: Mapping<UserGroupDID, Vec<Role>>,

        // map_role_to_permission : key - RoleDID, value- Vec<Permission>
        map_role_to_permission: Mapping<RoleDID, Vec<Permission>>,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error 
    {
        // Returned if userDID is the same as GroupDID
        UserGroupAreSame,

        // Returned if given Group does not exist
        GroupDoesNotExist,

        // Returned if given User does not exist
        UserOrGroupDoesNotExist,

        // Returned if the User is not part of the Group
        UserOrGroupDoesNotExistInGroup,

        // Returned if the User or the Group has been in the Group already
        GroupHasUserOrGroupAlready,

        // Returned if the User or Group has belonged in the Group already
        UserOrGroupBelongsGroupAlready,

        // Returned if the Group is not part of the User
        GroupDoesNotExistInUserGroup,

        // Returned if the Role does exist for the User or Group
        RoleDoesNotExistForUserOrGroup,

        // Returned if the Role already in the User or Group
        UserOrGroupHasRoleAlready,

        // Returned if the Role does not exists
        RoleDoesNotExist,

        // Returned if the Permission does not exists for Role
        PermissionNotExistInRole,
     
        // Returned if the Permission is already in the Role
         RoleHasPermissionAlready,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl RBAC {
        
        #[ink(constructor, payable)]
        pub fn new() -> Self 
        {
            ink_lang::codegen::initialize_contract(|_| {})
        }

        #[ink(constructor, payable)]
        pub fn default() -> Self 
        {
            ink_lang::codegen::initialize_contract(|_| {})
        }

        fn insert_group_has(&mut self, group_did: &GroupDID, user_did: &UserDID) ->Result<()> {
            let user_group = UserGroupEntity{ id: *user_did, is_group: false };
            let mut vec_user_group = 
                self.map_group_has.get(&group_did).unwrap_or_else(Vec::new);
            if vec_user_group.contains(&user_group) {
                return Err(Error::GroupHasUserOrGroupAlready);
            }
            vec_user_group.push(user_group);
            self.map_group_has.insert(*group_did, &vec_user_group);
            Ok(())
        }

        fn insert_user_group_belongs(&mut self, user_group_entity: UserGroupEntity, group_did: &GroupDID) -> Result<()> {
            let mut vec_group = 
                self.map_user_group_entity_belong.get(&user_group_entity).unwrap_or_else(Vec::new);
            if vec_group.contains(group_did) {
                return Err(Error::UserOrGroupBelongsGroupAlready);
            }
            vec_group.push(*group_did);
            self.map_user_group_entity_belong.insert(&user_group_entity, &vec_group);
            Ok(())
        }

        // Add user to group
        #[ink(message)]
        pub fn add_user_to_group(&mut self, user_did: UserDID, group_did: GroupDID) -> Result<()> {
            if group_did == user_did ||
                // user_did is the same as group id
                self.map_group_has.get(&user_did).is_some() ||
                // group id is the same as user id
                self.map_user_group_entity_belong.get(&UserGroupEntity {
                    id: group_did,
                    is_group: false
            }).is_some() {
                return Err(Error::UserGroupAreSame);
            }

            self.insert_group_has(&group_did, &user_did)?;
            self.insert_user_group_belongs(UserGroupEntity{ id: user_did, is_group: false }, &group_did)?;
            Ok(())
        }

        fn remove_group_has(&mut self, group_did: &GroupDID, user_did: &UserDID) -> Result<()> {
            let mut groups = self.map_group_has
                .get(group_did)
                .ok_or(Error::GroupDoesNotExist)?;
            let index = groups
                .iter()
                .position(|r| r.id == *user_did)
                .ok_or(Error::UserOrGroupDoesNotExistInGroup)?;
            groups.remove(index);
            self.map_group_has.insert(group_did, &groups);
            Ok(())
        }

        fn remove_user_group_belongs(&mut self, user_did: &UserDID, group_did: &GroupDID) -> Result<()> {
            let user = UserGroupEntity{ id: *user_did, is_group: false };
            let mut groups = self.map_user_group_entity_belong
                .get(&user)
                .ok_or(Error::UserOrGroupDoesNotExist)?;
            let index = groups
                .iter()
                .position(|r| *r == *group_did)
                .ok_or(Error::GroupDoesNotExistInUserGroup)?;
            groups.remove(index);
            self.map_user_group_entity_belong.insert(&user, &groups);
            Ok(())
        }

        // Remove user from group
        #[ink(message)]
        pub fn remove_user_from_group(&mut self, user_did: UserDID, group_did: GroupDID) -> Result<()> {
            self.remove_group_has(&group_did, &user_did)?;
            self.remove_user_group_belongs(&user_did, &group_did)?;
            Ok(())
        }

        // Read User Group, return all users in group
        // Example:
        // GroupsDID has UserDID1, UserDID2
        // Return UserDID1, UserDID2
        #[ink(message)]
        pub fn read_user_group(&self, group_did: GroupDID) -> Vec<UserDID> {
            self.map_group_has.get(&group_did).unwrap_or_else(Vec::new)
                .iter()
                .map(|user| user.id)
                .collect()
        }

        fn read_user_belongs(&self, user_did: UserDID) -> Vec<GroupDID> {
            let user_entity = UserGroupEntity{ id: user_did, is_group: false };
            self.read_user_group_entity_belongs(&user_entity)
        }

        fn read_group_belongs(&self, group_did: GroupDID) -> Vec<GroupDID> {
            let group_entity = UserGroupEntity{ id: group_did, is_group: true };
            self.read_user_group_entity_belongs(&group_entity)
        }

        fn read_user_group_entity_belongs(&self, user_group_entity: &UserGroupEntity) -> Vec<GroupDID> {
            self.map_user_group_entity_belong.get(user_group_entity).unwrap_or_else(Vec::new)
                .iter()
                .copied()
                .collect()
        }

        // Add User or Group to the Role
        #[ink(message)]
        pub fn add_user_or_group_to_role(&mut self, user_or_group_did: UserGroupDID, role_did: RoleDID) -> Result<()> {
            let role = Role{id: role_did};
            let mut vec_role = self.map_user_group_to_role.get(&user_or_group_did).unwrap_or_else(Vec::new);
            if vec_role.contains(&role) {
                return Err(Error::UserOrGroupHasRoleAlready);
            }
            vec_role.push(role);
            self.map_user_group_to_role.insert(user_or_group_did, &vec_role);
            Ok(())
        }

        // Remove User or Group from the Role
        #[ink(message)]
        pub fn remove_user_or_group_from_role(&mut self, user_or_group_did: UserGroupDID, role_did: RoleDID) -> Result<()> {
            let mut roles = self.map_user_group_to_role
                .get(&user_or_group_did)
                .ok_or(Error::UserOrGroupDoesNotExist)?;
            let index = roles
                .iter()
                .position(|r| r.id == role_did)
                .ok_or(Error::RoleDoesNotExistForUserOrGroup)?;
            roles.remove(index);
            self.map_user_group_to_role.insert(&user_or_group_did, &roles);
            Ok(())
        }

        fn get_role(&self, user_or_group_did: &UserGroupDID) -> Vec<RoleDID>{
            self.map_user_group_to_role.get(user_or_group_did).unwrap_or_else(Vec::new)
                .iter()
                .map(|role| role.id)
                .collect()
        }

        // Read User/Group Roles
        #[ink(message)]
        pub fn read_user_or_group_roles(&self, user_or_group_did: UserGroupDID) ->Vec<RoleDID> {
            let mut vec_roles = Vec::new();
            vec_roles.append(&mut self.get_role(&user_or_group_did));

            // The User/Group DID isn't the same, so just try to get the roles
            self.read_user_belongs(user_or_group_did)
                .iter()
                .for_each(|group| 
                    vec_roles.append(&mut self.get_role(group))
            );

            self.read_group_belongs(user_or_group_did)
                .iter()
                .for_each(|group| 
                    vec_roles.append(&mut self.get_role(group))
            );

            vec_roles.into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        }
        

        // Add Role to the Permission
        #[ink(message)]
        pub fn add_role_to_permission(&mut self, role_did: RoleDID, permission_did: PermissionDID) -> Result<()> {
            let permission = Permission{ id: permission_did};
            let mut vec_permission = self.map_role_to_permission.get(&role_did).unwrap_or_else(Vec::new);

            if vec_permission.contains(&permission) {
                return Err(Error::RoleHasPermissionAlready);
            }
            vec_permission.push(permission);
            self.map_role_to_permission.insert(role_did, &vec_permission);
            Ok(())
        }

        // Remove Role from the Permission
        #[ink(message)]
        pub fn remove_role_from_permission(&mut self, role_did: RoleDID, permission_did: PermissionDID) -> Result<()> {
            let mut perms = self.map_role_to_permission.get(&role_did).ok_or(Error::RoleDoesNotExist)?;
            let index = perms
                .iter()
                .position(|r| r.id == permission_did)
                .ok_or(Error::PermissionNotExistInRole)?;

            perms.remove(index);
            self.map_role_to_permission.insert(&role_did, &perms);
            Ok(())
        }
          
        // Read Permission for Roles
        #[ink(message)]
        pub fn read_permissions(&self, role_did: RoleDID) ->Vec<PermissionDID> {
            self.map_role_to_permission.get(&role_did).unwrap_or_else(Vec::new)
                .iter()
                .map(|x| x.id )
                .collect()
        }

        #[ink(message)]
        pub fn check_access(&self, user_did: UserDID, permission_did: PermissionDID) -> bool {
            self.read_user_or_group_roles(user_did)
                .iter()
                .any(|&role| {
                    self.read_permissions(role).contains(&permission_did)
            })
        }
    }
 
    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    
    #[cfg(test)]
    mod tests 
    {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        #[ink::test]
        fn add_single_user_to_group_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 1);

            let vec_group_in_user = rbac.read_user_belongs([2;32]);
            assert_eq!(vec_group_in_user.len(), 1);
        }

        #[ink::test]
        fn add_single_user_to_groups_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();
            rbac.add_user_to_group([2;32], [4;32]).unwrap();


            assert_eq!(
                rbac.add_user_to_group([2;32], [3;32]),
                Ok(())
            );

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 1);
            let vec_users_in_group = rbac.read_user_group([4;32]);
            assert_eq!(vec_users_in_group.len(), 1);
            let vec_users_in_group = rbac.read_user_group([3;32]);
            assert_eq!(vec_users_in_group.len(), 1);

            let vec_group_in_user = rbac.read_user_belongs([2;32]);
            assert_eq!(vec_group_in_user.len(), 3);
        }

        #[ink::test]
        fn add_users_to_single_group_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32], [3;32]).unwrap();
            rbac.add_user_to_group([2;32], [3;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([3;32]);
            assert_eq!(vec_users_in_group.len(), 2);

            let vec_group_in_user = rbac.read_user_belongs([1;32]);
            assert_eq!(vec_group_in_user.len(), 1);
            let vec_group_in_user = rbac.read_user_belongs([2;32]);
            assert_eq!(vec_group_in_user.len(), 1);
        }

        #[ink::test]
        fn add_single_user_to_group_already() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();
            assert_eq!(
                rbac.add_user_to_group([2;32], [1;32]),
                Err(Error::GroupHasUserOrGroupAlready)
            );
        }

        #[ink::test]
        fn remove_users_from_group_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();
            rbac.add_user_to_group([3;32], [1;32]).unwrap();
            rbac.add_user_to_group([4;32], [1;32]).unwrap();

            // remove user from group
            assert_eq!(
                rbac.remove_user_from_group([4;32], [1;32]),
                Ok(())
            );

            // new user count should be reduced 
            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 2);
            let vec_group_in_user = rbac.read_user_belongs([4;32]);
            assert_eq!(vec_group_in_user.len(), 0);
        }

        #[ink::test]
        fn remove_user_from_groups_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32], [2;32]).unwrap();
            rbac.add_user_to_group([1;32], [3;32]).unwrap();

            // remove user from group
            assert_eq!(
                rbac.remove_user_from_group([1;32], [2;32]),
                Ok(())
            );

            // new user count should be reduced 
            let vec_users_in_group = rbac.read_user_group([3;32]);
            assert_eq!(vec_users_in_group.len(), 1);
            assert_eq!(vec_users_in_group[0], [1;32]);
        }

        #[ink::test]
        fn remove_user_from_groups_and_added_again() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32], [2;32]).unwrap();
            rbac.add_user_to_group([1;32], [3;32]).unwrap();
            rbac.remove_user_from_group([1;32], [2;32]).unwrap();

            assert_eq!(
                rbac.add_user_to_group([1;32], [2;32]),
                Ok(())
            );

            let vec_users_in_group = rbac.read_user_group([2;32]);
            assert_eq!(vec_users_in_group.len(), 1);
            assert_eq!(vec_users_in_group[0], [1;32]);
            let vec_users_in_group = rbac.read_user_group([3;32]);
            assert_eq!(vec_users_in_group.len(), 1);
            assert_eq!(vec_users_in_group[0], [1;32]);
        }

        //remove_user_from_group_wrong_group() when wrong group id passed
        #[ink::test]
        fn remove_user_from_empty_group_fail() {
            let mut rbac = RBAC::default();

            assert_eq!(
                rbac.remove_user_from_group([2;32], [3;32]),
                Err(Error::GroupDoesNotExist)
            );
        }

        //remove_user_from_group_wrong_group() when wrong group id passed
        #[ink::test]
        fn remove_user_from_group_wrong_group_fail() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();
            rbac.add_user_to_group([3;32], [1;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 2);

            // remove user from group where group id is wrong
            assert_eq!(
                rbac.remove_user_from_group([2;32], [4;32]),
                Err(Error::GroupDoesNotExist)
            );
        }


        //user's and group's DID are the same
        #[ink::test]
        fn user_group_did_are_same() {
            let mut rbac = RBAC::default();
            assert_eq!(rbac.add_user_to_group([1;32], [1;32]),
                Err(Error::UserGroupAreSame)
            );
        }

        //user's and group's DID are the same
        #[ink::test]
        fn user_group_did_conflict() {
            let mut rbac = RBAC::default();
            let (user_did, group_did) = ([2;32], [1;32]);
            rbac.add_user_to_group(user_did, group_did).unwrap();

            assert_eq!(rbac.add_user_to_group(group_did, [3;32]),
                Err(Error::UserGroupAreSame)
            );

            assert_eq!(rbac.add_user_to_group([3;32], user_did),
                Err(Error::UserGroupAreSame)
            );
        }

        //remove_user_from_group_wrong_user() when wrong user id passed
        #[ink::test]
        fn remove_user_from_group_wrong_user() {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([2;32], [1;32]).unwrap();
            rbac.add_user_to_group([3;32], [1;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 2);

            // remove user from group where group id is wrong
            assert_eq!(
                rbac.remove_user_from_group([4;32], [1;32]),
                Err(Error::UserOrGroupDoesNotExistInGroup)
            );
        }

        #[ink::test]
        fn read_user_group_empty_works() {
            let rbac = RBAC::default();
            
            // pass wrong group id
            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(), 0);
            let vec_group_in_user = rbac.read_user_belongs([1;32]);
            assert_eq!(vec_group_in_user.len(), 0);
        }

        // Assign single roles to single user/group: one to one
        #[ink::test]
        fn assign_single_role_to_user_or_group() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 1);
        }

        #[ink::test]
        fn assign_single_role_to_user_already() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
            assert_eq!(
                rbac.add_user_or_group_to_role([1;32], [10;32]),
                Err(Error::UserOrGroupHasRoleAlready),
            );
        }

        // Assign muliple roles to single user/group: many to one
        #[ink::test]
        fn assign_roles_to_user_or_group() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32], [11;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32], [12;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 3);
        }

        #[ink::test]
        fn assign_role_to_users_or_groups() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
            rbac.add_user_or_group_to_role([2;32], [10;32]).unwrap();
            rbac.add_user_or_group_to_role([3;32], [10;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 1);
            let vec_roles = rbac.read_user_or_group_roles([2;32]);
            assert_eq!(vec_roles.len(), 1);
            let vec_roles = rbac.read_user_or_group_roles([3;32]);
            assert_eq!(vec_roles.len(), 1);
        }

        #[ink::test]
        fn assign_multiple_role_to_user_with_group() {
            let mut rbac = RBAC::default();
            let user_did = [1;32];
            let group_did = [2;32];
            let user_role_did = [10;32];
            let group_role_did = [11;32];
            rbac.add_user_or_group_to_role(user_did, user_role_did).unwrap();
            rbac.add_user_to_group(user_did, group_did).unwrap();
            rbac.add_user_or_group_to_role(group_did, group_role_did).unwrap();
            rbac.add_user_or_group_to_role(group_did, user_role_did).unwrap();

            let vec_roles = rbac.read_user_or_group_roles(user_did);
            assert_eq!(vec_roles.len(), 2);
        }

        #[ink::test]
        fn remove_role_from_single_user() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();

            // remove user/group from role
            assert_eq!(
                rbac.remove_user_or_group_from_role([1;32], [10;32]),
                Ok(())
            );

            // new user count should be reduced 
            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 0)
        }

        #[ink::test]
        fn remove_role_from_user_or_group_works() {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32], [11;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32], [12;32]).unwrap();

            let mut vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 3);

            // remove user/group from role
            assert_eq!(
                rbac.remove_user_or_group_from_role([1;32], [12;32]),
                Ok(())
            );

            // new user count should be reduced 
            vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(), 2)
        }

         //remove_user_or_group_from_role_wrong_user_group() when wrong user/group id passed
         #[ink::test]
         fn remove_user_or_group_from_role_wrong_user_group() {
             let mut rbac = RBAC::default();
             rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
             rbac.add_user_or_group_to_role([1;32], [11;32]).unwrap();
 
             // delete user/group from role where group id is wrong
             assert_eq!(
                 rbac.remove_user_or_group_from_role([2;32], [10;32]),
                 Err(Error::UserOrGroupDoesNotExist)
             );
         }
 
         //remove_user_or_group_from_role_wrong_role() when wrong role id passed
         #[ink::test]
         fn remove_user_or_group_from_role_wrong_role() {
             let mut rbac = RBAC::default();
             rbac.add_user_or_group_to_role([1;32], [10;32]).unwrap();
             rbac.add_user_or_group_to_role([1;32], [11;32]).unwrap();
 
             // remove user/group from role where role id is wrong
             assert_eq!(
                 rbac.remove_user_or_group_from_role([1;32], [12;32]),
                 Err(Error::RoleDoesNotExistForUserOrGroup)
             );
         }
 
         // Assign single permission to single role: one to one
        #[ink::test]
        fn assign_single_permission_to_role() {
            let mut rbac = RBAC::default();
            let perm_1 = [20;32];
            let role_1 = [10;32];
            rbac.add_role_to_permission(role_1, perm_1).unwrap();

            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 1);
        }

        #[ink::test]
        fn assign_single_permission_to_role_multiple_times() {
            let mut rbac = RBAC::default();
            let perm_1 = [20;32];
            let role_1 = [10;32];
            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            assert_eq!(
                rbac.add_role_to_permission(role_1, perm_1),
                Err(Error::RoleHasPermissionAlready)
            );
        }

        // Assign muliple permission to single role: many to one
        #[ink::test]
        fn assign_multiple_permission_to_role() {
            let mut rbac = RBAC::default();
            let role_1 = [10;32];
            let (perm_1, perm_2, perm_3) = ([20;32], [21;32], [22;32]);
            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            rbac.add_role_to_permission(role_1, perm_2).unwrap();
            rbac.add_role_to_permission(role_1, perm_3).unwrap();

            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 3);
        }

        // Assign muliple permission to muliple role: many to many
        #[ink::test]
        fn assign_single_permission_to_multiple_role() {
            let mut rbac = RBAC::default();
            let (role_1, role_2) = ([10;32], [11;32]);
            let perm_1 = [20;32];
            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            rbac.add_role_to_permission(role_2, perm_1).unwrap();

            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 1);

            let vec_roles = rbac.read_permissions(role_2);
            assert_eq!(vec_roles.len(), 1);
        }

        #[ink::test]
        fn remove_signle_role_from_permission_works() {
            let mut rbac = RBAC::default();
            let role_1 = [10;32];
            let perm_1 = [20;32];
            rbac.add_role_to_permission(role_1, perm_1).unwrap();

            // delete role from permission
            assert_eq!(
                rbac.remove_role_from_permission(role_1, perm_1),
                Ok(())
            );

            // new permission count should be reduced 
            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 0)
        }

        #[ink::test]
        fn remove_non_exist_permission_fail() {
            let mut rbac = RBAC::default();

            assert_eq!(
                rbac.remove_role_from_permission([10;32], [20;32]),
                Err(Error::RoleDoesNotExist)
            );
        }

        #[ink::test]
        fn remove_role_from_permission_works() {
            let mut rbac = RBAC::default();
            let role_1 = [10;32];
            let (perm_1, perm_2, perm_3) = ([20;32], [21;32], [22;32]);
            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            rbac.add_role_to_permission(role_1, perm_2).unwrap();
            rbac.add_role_to_permission(role_1, perm_3).unwrap();

            // delete role from permission
            assert_eq!(
                rbac.remove_role_from_permission(role_1, perm_3),
                Ok(())
            );

            // new permission count should be reduced 
            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 2)
        }

        //remove_remove_role_from_permission_wrong_role() when wrong role id passed
        #[ink::test]
        fn remove_role_from_permission_wrong_role() {
            let (perm_1, perm_2) = ([20;32], [21;32]);
            let (role_1, role_not_exist) = ([10;32], [13;32]);
            let mut rbac = RBAC::default();
            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            rbac.add_role_to_permission(role_1, perm_2).unwrap();
 
            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 2);
 
            // delete role from permission where role id is wrong
            assert_eq!(
                rbac.remove_role_from_permission(role_not_exist, perm_1),
                Err(Error::RoleDoesNotExist)
            );
        }
 
        //remove_role_from_permission_wrong_permission() when wrong permission id passed
        #[ink::test]
        fn remove_role_from_permission_wrong_permission() {
            let mut rbac = RBAC::default();
            let role_1 = [10;32];
            let (perm_1, perm_2, perm_not_exist) = ([20;32], [21;32], [22;32]);

            rbac.add_role_to_permission(role_1, perm_1).unwrap();
            rbac.add_role_to_permission(role_1, perm_2).unwrap();
 
            let vec_roles = rbac.read_permissions(role_1);
            assert_eq!(vec_roles.len(), 2);
 
            // delete role from permission where permission id is wrong
            assert_eq!(
                rbac.remove_role_from_permission(role_1, perm_not_exist),
                Err(Error::PermissionNotExistInRole)
            );
        }
 
        #[ink::test]
        fn read_single_user_perm_empty() {
            let rbac = RBAC::default();

            assert_eq!(rbac.check_access([1;32], [11;32]), false);
        }


        #[ink::test]
        fn read_single_user_permission() {
            let mut rbac = RBAC::default();
            let user_did = [1;32];
            let user_role_did = [10;32];
            let user_permission_did = [11;32];

            assert_eq!(rbac.check_access(user_did, user_permission_did), false);
            rbac.add_user_or_group_to_role(user_did, user_role_did).unwrap();
            rbac.add_role_to_permission(user_role_did, user_permission_did).unwrap();
            assert_eq!(rbac.check_access(user_did, user_permission_did), true);
        }

        #[ink::test]
        fn read_user_in_group_permission() {
            let mut rbac = RBAC::default();
            let user_did = [1;32];
            let group_did = [2;32];
            let group_role_did = [10;32];
            let group_permission_did = [11;32];

            rbac.add_user_to_group(user_did, group_did).unwrap();
            rbac.add_user_or_group_to_role(group_did, group_role_did).unwrap();
            rbac.add_role_to_permission(group_role_did, group_permission_did).unwrap();
            assert_eq!(rbac.check_access(user_did, group_permission_did), true);
        }
    }
}
