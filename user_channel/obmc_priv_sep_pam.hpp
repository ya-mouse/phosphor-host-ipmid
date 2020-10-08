#pragma once

#include <security/pam_appl.h>
#include <boost/utility/string_view.hpp>
#include <user_channel/obmc_priv_sep.hpp>

#include <cstring>
#include <memory>

namespace obmc_priv {

struct prsp_pam_req {
  uint8_t pam_name_len;
  uint8_t user_len;
  uint8_t passwd_len;
  char pam_name[64];
  char user[256];
  char passwd[256];
};

struct prsp_pam_resp {
  int status;
};


inline int pamUpdatePassword(const char *pamName,
                             const std::string& username,
                             const std::string& password);

inline int pamAuthenticateUser(const char *pamName,
                               const std::string_view username,
                               const std::string_view password);

inline int pam_handle_requests(int fd) {
  struct obmc_priv::prsp_proto hdr;
  struct obmc_priv::prsp_pam_req req;
  struct obmc_priv::prsp_pam_resp resp;

  for (;;) {
    ::memset(&hdr, 0, sizeof(hdr));
    ::memset(&req, 0, sizeof(req));
    ::memset(&resp, 0, sizeof(resp));

    int rc = obmc_priv::read_data(fd, &hdr, sizeof(struct obmc_priv::prsp_proto));
    if (rc < 0) {
      return rc;
    }

    if (hdr.magic != OBMC_PRIV_PROTO_MAGIC) {
      return -EINVAL;
    }

    switch (hdr.type) {
      case obmc_priv::TYPE_PAM_AUTH:
      case obmc_priv::TYPE_PAM_CHANGE:
        rc = obmc_priv::read_data(fd, &req, sizeof(req));
        if (rc < 0) {
          return rc;
        }

        req.pam_name[req.pam_name_len] = '\0';
        req.user[req.user_len] = '\0';
        req.passwd[req.passwd_len] = '\0';

        if (hdr.type == obmc_priv::TYPE_PAM_CHANGE) {
          resp.status = obmc_priv::pamUpdatePassword(req.pam_name, req.user, req.passwd);
        } else {
          resp.status = obmc_priv::pamAuthenticateUser(req.pam_name, req.user, req.passwd);
        }

        rc = obmc_priv::write_data(fd, obmc_priv::TYPE_RESPONSE, &resp, sizeof(resp));
        if (rc < 0) {
          return rc;
        }
        break;

      default:
        return -EINVAL;
    }
  }

  return 0;
}


static int do_pam_request(int fd, const char *pamName, uint32_t type, const char *user, const char *passwd) {
  struct obmc_priv::prsp_proto hdr;
  struct obmc_priv::prsp_pam_req req;
  struct obmc_priv::prsp_pam_resp resp;
  
  if (user == NULL || passwd == NULL || pamName == NULL) {
    return -EINVAL;
  }

  ::memset(&req, 0, sizeof(req));
  ::memset(&resp, 0, sizeof(resp));
  req.pam_name_len = strlen(pamName);
  req.user_len = strlen(user);
  req.passwd_len = strlen(passwd);

  ::memcpy(req.pam_name, pamName, req.pam_name_len + 1);
  ::memcpy(req.user, user, req.user_len + 1);
  ::memcpy(req.passwd, passwd, req.passwd_len + 1);

  int r = write_data(fd, type, &req, sizeof(req));
  if (r < 0) {
    return r;
  }

  ::memset(&hdr, 0, sizeof(hdr));
  r = obmc_priv::read_data(fd, &hdr, sizeof(hdr));
  if (r < 0 || hdr.magic != OBMC_PRIV_PROTO_MAGIC) {
    return r < 0 ? r : -EINVAL;
  }

  r = read_data(fd, &resp, sizeof(resp));
  if (r < 0) {
    return r;
  }
  return resp.status;
}


// function used to get user input
inline int pamFunctionConversation(int numMsg, const struct pam_message** msg,
                                   struct pam_response** resp, void* appdataPtr)
{
    if (appdataPtr == nullptr)
    {
        return PAM_AUTH_ERR;
    }
    char* appPass = reinterpret_cast<char*>(appdataPtr);
    size_t appPassSize = std::strlen(appPass);
    char* pass = reinterpret_cast<char*>(malloc(appPassSize + 1));
    if (pass == nullptr)
    {
        return PAM_AUTH_ERR;
    }

    std::strncpy(pass, appPass, appPassSize + 1);

    *resp = reinterpret_cast<pam_response*>(
        calloc(static_cast<size_t>(numMsg), sizeof(struct pam_response)));

    if (resp == nullptr)
    {
        free(pass);
        return PAM_AUTH_ERR;
    }

    for (int i = 0; i < numMsg; ++i)
    {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }

        /* Assume PAM is only prompting for the password as hidden input */
        resp[i]->resp = pass;
    }

    return PAM_SUCCESS;
}

/**
 * @brief Attempt username/password authentication via PAM.
 * @param username The provided username aka account name.
 * @param password The provided password.
 * @returns PAM error code or PAM_SUCCESS for success. */
inline int pamAuthenticateUser(const char *pamName,
                               const std::string_view username,
                               const std::string_view password)
{
    std::string userStr(username);
    std::string passStr(password);
    const struct pam_conv localConversation = {
        pamFunctionConversation, const_cast<char*>(passStr.c_str())};
    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    if (pamName == NULL)
    {
        return PAM_AUTH_ERR;
    }

    int retval = pam_start(pamName, userStr.c_str(), &localConversation,
                           &localAuthHandle);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_authenticate(localAuthHandle,
                              PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, PAM_SUCCESS); // ignore retval
        return retval;
    }

    /* check that the account is healthy */
    retval = pam_acct_mgmt(localAuthHandle, PAM_DISALLOW_NULL_AUTHTOK);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, PAM_SUCCESS); // ignore retval
        return retval;
    }

    return pam_end(localAuthHandle, PAM_SUCCESS);
}

inline int pamUpdatePassword(const char *pamName,
                             const std::string& username,
                             const std::string& password)
{
    const struct pam_conv localConversation = {
        pamFunctionConversation, const_cast<char*>(password.c_str())};
    pam_handle_t* localAuthHandle = nullptr; // this gets set by pam_start

    if (pamName == NULL)
    {
        return PAM_AUTH_ERR;
    }

    int retval = pam_start(pamName, username.c_str(), &localConversation,
                           &localAuthHandle);

    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, PAM_SUCCESS);
        return retval;
    }

    return pam_end(localAuthHandle, PAM_SUCCESS);
}

inline int authenticateUser(int pamFd, const char *pamName, 
                            const std::string_view username,
                            const std::string_view password)
{
    if (pamFd != -1)
    {
        return obmc_priv::do_pam_request(
            pamFd, pamName, obmc_priv::TYPE_PAM_AUTH,
            const_cast<char*>(username.data()),
            const_cast<char*>(password.data()));
    }

    return obmc_priv::pamAuthenticateUser(pamName, username, password);
}

inline int updatePassword(int pamFd, const char *pamName,
                             const std::string& username,
                             const std::string& password)
{
    if (pamFd != -1)
    {
        return obmc_priv::do_pam_request(
            pamFd, pamName, obmc_priv::TYPE_PAM_CHANGE,
            username.c_str(), password.c_str());
    }

    return obmc_priv::pamUpdatePassword(pamName, username, password);
}

} // namespace obmc_priv
