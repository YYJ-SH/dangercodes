#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define MAX_USERNAME_LEN 39
#define SETTINGS_COUNT 10
#define MAX_USERS 100
#define INVALID_USER_ID -1
int userid_next = 0;
typedef struct {
    char username[MAX_USERNAME_LEN + 1];
    bool isAdmin;
    long userid;
    long setting[SETTINGS_COUNT];
} user_account;
user_account *accounts[MAX_USERS];
int create_user_account(bool isAdmin, const char *username) {
    if (userid_next >= MAX_USERS) {
        fprintf(stderr, "the maximum number of users have been exceeded");
        return INVALID_USER_ID;
    }    
    user_account *ua;
    if (strlen(username) > MAX_USERNAME_LEN) {
        fprintf(stderr, "the username is too long");
        return INVALID_USER_ID;
    }    
    ua = malloc(sizeof (user_account));
    if (ua == NULL) {
        fprintf(stderr, "malloc failed to allocate memory");
        return INVALID_USER_ID;
    }
    ua->isAdmin = isAdmin;
    ua->userid = userid_next++;
    strcpy(ua->username, username);
    memset(&ua->setting, 0, sizeof ua->setting);
    accounts[userid_next] = ua;
    return userid_next++;
}
bool update_username(int user_id, const char *new_name) {
  if (user_id < 0 || user_id >= MAX_USERS)
   return false;
  int length = strlen(accounts[user_id]->username);
  strncpy(accounts[user_id]->username+length, new_name, MAX_USERNAME_LEN);
  return true;
}
bool update_setting(int user_id, const char *index, const char *value) {
    if (user_id < 0 || user_id >= MAX_USERS)
        return false;
    char endptr;
    long i, v;
    i = strtol(index, &endptr, 10);
    if (endptr)
        return false;
    v = strtol(value, &endptr, 10);
    if (endptr || i < 0 || i >= SETTINGS_COUNT)
        return false;
    accounts[user_id]->setting[i] = v;
    return true;
}
bool is_admin(int user_id) {
    if (user_id < 0 || user_id >= MAX_USERS) {
        fprintf(stderr, "invalid user id");
        return false;
    }    
    return accounts[user_id]->isAdmin;
}
const char username(int user_id) {
    if (user_id < 0 || user_id >= MAX_USERS) {
        fprintf(stderr, "invalid user id");
        return NULL;
    }    
    return accounts[user_id]->username;
}