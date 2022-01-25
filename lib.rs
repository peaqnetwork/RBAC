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
        };
        use ink_storage::collections::HashMap;


    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout,Default)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            PartialOrd,
            Ord,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct UserGroupEntity 
    {
        id: [u8; 32],
        is_group: bool,
    }


    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout,Default)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            PartialOrd,
            Ord,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Role 
    {
        id: [u8; 32],
    }


    #[derive(scale::Encode, scale::Decode, Clone, SpreadLayout, PackedLayout,Default)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            PartialOrd,
            Ord,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Permission 
    {
        id: [u8; 32],
    }
    
    #[ink(storage)]
    #[derive(SpreadAllocate, Default)]
    pub struct RBAC
    {
    
        // map_user_to_group : key - GroupDID, value- Vec<UserGroupEntity>
        map_user_to_group: HashMap<[u8; 32], Vec<UserGroupEntity>>,

        // map_user_group_to_role : key - GroupDID/UserDID, value- Vec<Role>
        map_user_group_to_role: HashMap<[u8; 32], Vec<Role>>,

        // map_role_to_permission : key - RoleDID, value- Vec<Permission>
        map_role_to_permission: HashMap<[u8; 32], Vec<Permission>>,
        
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error 
    {
        // Returned if given Group does not exist
        GroupDoesNotExist,

        // Returned if given User does not exist
        UserDoesNotExist,

        // Returned if the User is not part of the Group
        UserDoesNotExistInGroup,

        // Returned if the Role does exist for the User or Group
        RoleDoesNotExistForUserOrGroup,

        // Returned if the User Or Group does exists
        UserOrGroupDoesNotExist,

        // Returned if the Role does not exists
        RoleDoesNotExist,

        // Returned if the Permission does not exists for Role
        PermissionNotExistInRole
       
    }
    pub type Result<T> = core::result::Result<T, Error>;

    impl RBAC {
        
        #[ink(constructor)]
        pub fn new() -> Self 
        {
            ink_lang::codegen::initialize_contract(|_| {})
        }

        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self 
        {
            RBAC 
            {
                map_user_to_group: HashMap::new(),
                map_user_group_to_role: HashMap::new(),
                map_role_to_permission: HashMap::new(), 
            }
        }

        // Add user to group
        #[ink(message)]
        pub fn add_user_to_group(&mut self, group_did: [u8; 32], user_did: [u8; 32]) -> Result<()>  
        {
            let user_group = UserGroupEntity{ id: user_did, is_group: false };
           
            if !self.map_user_to_group.contains_key(&group_did)
            {
                let mut vec_user_group = Vec::new();
                vec_user_group.push(user_group);
                self.map_user_to_group.insert(group_did, vec_user_group);
            }
            else
            {
                self.map_user_to_group[&group_did].push(user_group);
            }
            Ok(())
        }

        // Remove user from group
        #[ink(message)]
        pub fn remove_user_from_group(&mut self, group_did: [u8; 32], user_did: [u8; 32]) -> Result<()>  
        {
            if !self.map_user_to_group.contains_key(&group_did)
            {
                return Err(Error::GroupDoesNotExist)
            }
            else
            {
                if let Some(index) = self.map_user_to_group[&group_did].iter().position(|r| r.id == user_did) 
                {
                    self.map_user_to_group[&group_did].remove(index);
                } 
                else 
                {
                    return Err(Error::UserDoesNotExistInGroup)
                }
            }
            Ok(())
        }

        // Read User Group
        #[ink(message)]
        pub fn read_user_group(&mut self,group_did: [u8; 32]) -> Vec<[u8; 32]>  
        {
            let mut vec_user_group = Vec::new();

            if self.map_user_to_group.contains_key(&group_did) 
            {
                for user in self.map_user_to_group[&group_did].iter() 
                {
                    vec_user_group.push(user.id);
                }
            }             
            vec_user_group
           
        }


       // Add User or Group to the Role
       #[ink(message)]
       pub fn add_user_or_group_to_role(&mut self, user_or_group_did: [u8; 32], role_did: [u8; 32]) -> Result<()>  
       {
            let role = Role{ id: role_did};
           
            if !self.map_user_group_to_role.contains_key(&user_or_group_did)
            {
                let mut vec_role = Vec::new();
                vec_role.push(role);
                self.map_user_group_to_role.insert(user_or_group_did, vec_role);
            }
            else
            {
                self.map_user_group_to_role[&user_or_group_did].push(role);

            }
            Ok(())
        }

        // Remove User or Group from the Role
        #[ink(message)]
        pub fn remove_user_or_group_from_role(&mut self, user_or_group_did: [u8; 32], role_did: [u8; 32]) -> Result<()> 
        {
            if !self.map_user_group_to_role.contains_key(&user_or_group_did)
            {
                return Err(Error::UserOrGroupDoesNotExist)
            }
            else
            {
                if let Some(index) = self.map_user_group_to_role[&user_or_group_did].iter().position(|r| r.id == role_did) 
                {
                    self.map_user_group_to_role[&user_or_group_did].remove(index);
                } 
                else 
                {
                    return Err(Error::RoleDoesNotExistForUserOrGroup)
                }
            }
            Ok(())
        }
          
        // Read User/Group Roles
        #[ink(message)]
        pub fn read_user_or_group_roles(&mut self, user_or_group_did: [u8; 32]) ->Vec<[u8; 32]>
        {
            let mut vec_roles = Vec::new();

            if self.map_user_group_to_role.contains_key(&user_or_group_did) 
            {
                for role in self.map_user_group_to_role[&user_or_group_did].iter() 
                {
                    vec_roles.push(role.id);

                }
            }                 
            vec_roles
        }
        

        // Add Role to the Permission
        #[ink(message)]
        pub fn add_role_to_permission(&mut self, role_did: [u8; 32], permission_did: [u8; 32]) -> Result<()>  
        {
            let permission = Permission{ id: permission_did};
           
            if !self.map_role_to_permission.contains_key(&role_did)
            {
                let mut vec_permission = Vec::new();
                vec_permission.push(permission);
                self.map_role_to_permission.insert(role_did, vec_permission);
            }
            else
            {
                self.map_role_to_permission[&role_did].push(permission);
            }
            Ok(())
        }

        // Remove Role from the Permission
        #[ink(message)]
        pub fn remove_role_from_permission(&mut self, role_did: [u8; 32], permission_did: [u8; 32]) -> Result<()> 
        {
            if !self.map_role_to_permission.contains_key(&role_did)
            {
                return Err(Error::RoleDoesNotExist)
            }
            else
            {
                if let Some(index) = self.map_role_to_permission[&role_did].iter().position(|r| r.id == permission_did) 
                {
                    self.map_role_to_permission[&role_did].remove(index);
                } 
                else 
                {
                    return Err(Error::PermissionNotExistInRole)
                }
            }
            Ok(())
        }
          
        // Read User/Group Roles
        #[ink(message)]
        pub fn read_permissions(&mut self, role_did: [u8; 32]) ->Vec<[u8; 32]>
        {
            let mut vec_permission = Vec::new();

            if self.map_role_to_permission.contains_key(&role_did) 
            {
                for permission in self.map_role_to_permission[&role_did].iter() 
                {
                    vec_permission.push(permission.id);
                }
            }                 
            vec_permission
        }
        /* New – take user or group did to find in first map. If group, it will be a key 
        Else it will be a value inside vector. Find the group for userDID. 
        Pass user or group did  to find in second map and check for roles. 
        For each matched roles see in third map to compare passed permission id == value in vector in map 
        
        CheckAccess(&mut self, user_did: [u8; 32], permission_did: [u8; 32]) 
        {
            // check in second map against user_did if user has direct roles
            // if user not found then check for values in first map and find a group he belongs to then serach in second map
            // based on matching roles found from second map, serach in third map against the permission_did passed
        }*/
     
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
        fn add_single_user_to_group_works()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32],[2;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),1);

        }

        #[ink::test]
        fn add_multiple_user_to_group_works()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32],[2;32]).unwrap();
            rbac.add_user_to_group([1;32],[3;32]).unwrap();
            rbac.add_user_to_group([1;32],[4;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),3);

        }

        #[ink::test]
        fn remove_user_from_group_works()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32],[2;32]).unwrap();
            rbac.add_user_to_group([1;32],[3;32]).unwrap();
            rbac.add_user_to_group([1;32],[4;32]).unwrap();

            let mut vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),3);

            // delete user from group
            assert_eq!(
                rbac.remove_user_from_group([1;32],[4;32]),
                Ok(())
            );

            // new user count should be reduced 
            vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),2)

        }

        //remove_user_from_group_wrong_group() when wrong group id passed
        #[ink::test]
        fn remove_user_from_group_wrong_group()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32],[2;32]).unwrap();
            rbac.add_user_to_group([1;32],[3;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),2);

            // delete user from group where group id is wrong
            assert_eq!(
                rbac.remove_user_from_group([2;32],[4;32]),
                Err(Error::GroupDoesNotExist)
            );
        }

        //remove_user_from_group_wrong_user() when wrong user id passed
        #[ink::test]
        fn remove_user_from_group_wrong_user()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_to_group([1;32],[2;32]).unwrap();
            rbac.add_user_to_group([1;32],[3;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),2);

            // delete user from group where group id is wrong
            assert_eq!(
                rbac.remove_user_from_group([1;32],[4;32]),
                Err(Error::UserDoesNotExistInGroup)
            );
        }

        #[ink::test]
        fn read_user_group_works()
        {
            let mut rbac = RBAC::default();
            
            // pass wrong group id
            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),0);

            rbac.add_user_to_group([1;32],[2;32]).unwrap();
            rbac.add_user_to_group([1;32],[3;32]).unwrap();

            let vec_users_in_group = rbac.read_user_group([1;32]);
            assert_eq!(vec_users_in_group.len(),2);
        }

        // Assign single roles to single one/group: many to one
        #[ink::test]
        fn assign_single_role_to_user_or_group()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(),1);

        }

        // Assign muliple roles to single user/group: many to one
        #[ink::test]
        fn assign_multiple_role_to_user_or_group()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32],[11;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32],[12;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(),3);

        }

        // Assign muliple roles to muliple user/group: many to many
        #[ink::test]
        fn assign_single_role_to_multiple_user_or_group()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
            rbac.add_user_or_group_to_role([2;32],[10;32]).unwrap();
            rbac.add_user_or_group_to_role([2;32],[11;32]).unwrap();

            let vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(),1);

            let vec_roles = rbac.read_user_or_group_roles([2;32]);
            assert_eq!(vec_roles.len(),2);

        }

        #[ink::test]
        fn remove_role_from_user_or_group_works()
        {
            let mut rbac = RBAC::default();
            rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32],[11;32]).unwrap();
            rbac.add_user_or_group_to_role([1;32],[12;32]).unwrap();

            let mut vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(),3);

            // delete user from group
            assert_eq!(
                rbac.remove_user_or_group_from_role([1;32],[12;32]),
                Ok(())
            );

            // new user count should be reduced 
            vec_roles = rbac.read_user_or_group_roles([1;32]);
            assert_eq!(vec_roles.len(),2)

        }

         //remove_user_or_group_from_role_wrong_user_group() when wrong user/group id passed
         #[ink::test]
         fn remove_user_or_group_from_role_wrong_user_group()
         {
             let mut rbac = RBAC::default();
             rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
             rbac.add_user_or_group_to_role([1;32],[11;32]).unwrap();
 
             let vec_roles = rbac.read_user_or_group_roles([1;32]);
             assert_eq!(vec_roles.len(),2);
 
             // delete user from group where group id is wrong
             assert_eq!(
                 rbac.remove_user_or_group_from_role([2;32],[10;32]),
                 Err(Error::UserOrGroupDoesNotExist)
             );
         }
 
         //remove_user_or_group_from_role_wrong_role() when wrong role id passed
         #[ink::test]
         fn remove_user_or_group_from_role_wrong_role()
         {
             let mut rbac = RBAC::default();
             rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
             rbac.add_user_or_group_to_role([1;32],[11;32]).unwrap();
 
             let vec_roles = rbac.read_user_or_group_roles([1;32]);
             assert_eq!(vec_roles.len(),2);
 
             // delete user from group where group id is wrong
             assert_eq!(
                 rbac.remove_user_or_group_from_role([1;32],[12;32]),
                 Err(Error::RoleDoesNotExistForUserOrGroup)
             );
         }
 
         #[ink::test]
         fn read_user_or_group_roles_works()
         {
             let mut rbac = RBAC::default();
             
             // pass wrong group id
             let vec_roles = rbac.read_user_or_group_roles([1;32]);
             assert_eq!(vec_roles.len(),0);
 
             rbac.add_user_or_group_to_role([1;32],[10;32]).unwrap();
             rbac.add_user_or_group_to_role([1;32],[11;32]).unwrap();
 
             let vec_roles = rbac.read_user_or_group_roles([1;32]);
             assert_eq!(vec_roles.len(),2);
         }

    }
}