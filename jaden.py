import re
import httpx
import uuid
import urllib.parse

# ----------------------------
# Utility: Extract UID from a profile URL.
# ----------------------------
def extract_uid(profile_url):
    """
    Given a Facebook profile URL, attempt to extract the numeric UID.
    It first checks if the URL is of the type 'profile.php?id=...'
    and if not, it searches for any long numeric sequence.
    """
    parsed = urllib.parse.urlparse(profile_url)
    qs = urllib.parse.parse_qs(parsed.query)
    if "id" in qs:
        uid = qs["id"][0]
        print("[RPW - PROCESSING]] Extracted UID from query parameter:", uid)
        return uid

    m = re.search(r'(\d{5,})', profile_url)
    if m:
        uid = m.group(1)
        print("[RPW - PROCESSING]] Extracted UID from URL path:", uid)
        return uid

    print("[RPW FAILURE] Could not extract UID from the provided URL.")
    return None

# ----------------------------
# Function to extract post ID (for shares/reacts/comments)
# ----------------------------
def extract_post_id(fb_url):
    """
    Extracts full Facebook post ID in format USERID_POSTID if available.
    """
    try:
        r = httpx.get(fb_url, follow_redirects=True)
        final_url = str(r.url)
    except Exception:
        final_url = fb_url

    print("[RPW - PROCESSING]] :", final_url)

    match = re.search(r"(\d{6,})/posts/(\d{6,})", final_url)
    if match:
        user_id = match.group(1)
        post_id = match.group(2)
        full_id = f"{user_id}_{post_id}"
        print("[RPW - PROCESSING]] Extracted Post ID:", full_id)
        return full_id

    patterns = [
        r"permalink/(\d+)",
        r"posts/(\d+)",
        r"videos/(\d+)",
        r"photo\.php\?fbid=(\d+)",
        r"story_fbid=(\d+)",
        r"photos/[^/]+/(\d+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, final_url)
        if match:
            post_id = match.group(1)
            print("[RPW - PROCESSING]] Extracted Post ID:", post_id)
            return post_id

    print("[RPW FAILURE] Could not extract post ID.")
    return None

# ----------------------------
# Function to auto share a post
# ----------------------------
def auto_share_post(tokens, fb_url):
    post_id = extract_post_id(fb_url)
    
    if post_id:
        share_data = {
            'access_token': tokens[0],
            'object_attachment': post_id
        }
        res = httpx.post("https://graph.facebook.com/v21.0/me/feed", data=share_data).json()
        
        if isinstance(res, dict) and res.get('id'):
            print(f"[+] POST RESHARED SUCCESSFULLY! NEW POST ID: {res['id']}")
            return
        elif isinstance(res, dict) and res.get("error", {}).get("code") == 100:
            print("[RPW FAILURE] Object attachment failed, trying fallback method...")
        else:
            print("[RPW FAILURE] Unexpected error during share:")
            print(res)
            return

    try:
        share_data = {
            'access_token': tokens[0],
            'link': fb_url
        }
        res = httpx.post("https://graph.facebook.com/v21.0/me/feed", data=share_data).json()
        if isinstance(res, dict) and res.get('id'):
            print(f"[+] Link posted successfully! New Post ID: {res['id']}")
        else:
            print("[RPW FAILURE] Failed to share link.")
            print(res)
    except Exception as e:
        print("[ERROR]", e)

# ----------------------------
# Function to auto react to a post
# ----------------------------
def auto_react_to_post(tokens, fb_url, reaction_type, target_reactions):
    post_id = extract_post_id(fb_url)
    if not post_id:
        print("[RPW FAILURE] Could not extract post ID.")
        return

    for _ in range(target_reactions):
        for token in tokens:
            try:
                url = f"https://graph.facebook.com/v21.0/{post_id}/reactions"
                payload = {
                    "access_token": token,
                    "type": reaction_type.upper()
                }
                res = httpx.post(url, data=payload).json()
                if isinstance(res, dict) and res.get("success"):
                    print(f"[+] Reacted with {reaction_type.upper()} to post {post_id}")
                    break
                else:
                    print("[RPW FAILURE] Failed to react:")
                    print(res)
                    break
            except Exception as e:
                print("[ERROR]", e)

# ----------------------------
# Function to auto comment on a post
# ----------------------------
def auto_comment_post(tokens, fb_url, comment_text, target_comments):
    """
    Automatically comment on a Facebook post.
    It extracts the post ID from the given URL and posts the comment_text.
    The target_comments parameter specifies how many comments to post.
    """
    post_id = extract_post_id(fb_url)
    if not post_id:
        print("[RPW FAILURE] Could not extract post ID.")
        return

    count = 0
    for _ in range(target_comments):
        for token in tokens:
            try:
                url = f"https://graph.facebook.com/v21.0/{post_id}/comments"
                payload = {
                    "access_token": token,
                    "message": comment_text
                }
                res = httpx.post(url, data=payload).json()
                if isinstance(res, dict) and res.get("id"):
                    count += 1
                    print(f"[+] Commented on post {post_id}. New comment ID: {res['id']}")
                    break
                else:
                    print("[RPW FAILURE] Failed to comment:")
                    print(res)
                    break
            except Exception as e:
                print("[ERROR]", e)

# ----------------------------
# Function to get access token using user credentials
# ----------------------------
def get_access_token(user, passw):
    accessToken = '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    data = {
        'adid': str(uuid.uuid4()),
        'format': 'json',
        'device_id': str(uuid.uuid4()),
        'cpl': 'true',
        'family_device_id': str(uuid.uuid4()),
        'credentials_type': 'device_based_login_password',
        'error_detail_type': 'button_with_disabled',
        'source': 'device_based_login',
        'email': user,
        'password': passw,
        'access_token': accessToken,
        'generate_session_cookies': '1',
        'meta_inf_fbmeta': '',
        'advertiser_id': str(uuid.uuid4()),
        'currently_logged_in_userid': '0',
        'locale': 'en_US',
        'client_country_code': 'US',
        'method': 'auth.login',
        'fb_api_req_friendly_name': 'authenticate',
        'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        'api_key': '62f8ce9f74b12f84c123cc23437a4a32',
    }

    headers = {
        'User-Agent': 'FBAN/FB4A;FBAV/300.0.0.34.108;FBBV/200000000;',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'graph.facebook.com',
    }

    try:
        res = httpx.post("https://b-graph.facebook.com/auth/login", headers=headers, data=data).json()
        if 'access_token' in res and res['access_token'].startswith('EAAAA'):
            print(f"\n[EAAAA ACCESS TOKEN]\n{res['access_token']}")
            with open("/sdcard/666.txt", "a") as f:
                f.write(res['access_token'] + "\n")
        else:
            print("[RPW FAILURE] Failed to get access token.")
            print(res)
    except Exception as e:
        print("[ERROR]", e)

# ----------------------------
# Function to auto follow a profile given a profile URL or UID.
# ----------------------------
def auto_follow(tokens, input_value, follow_limit=None):
    """
    Automatically follow a profile. The input_value can be either:
      - A full profile URL (like "https://www.facebook.com/profile.php?id=61575358101686")
      - A numeric UID (e.g., "61575358101686")
    The function extracts the UID if needed and then sends a follow request.
    Optionally, a limit on the number of follow attempts can be set.
    """
    if input_value.startswith("http"):
        uid = extract_uid(input_value)
    else:
        uid = input_value

    if not uid:
        print("[RPW FAILURE] Could not determine UID for auto follow.")
        return

    count = 0
    for token in tokens:
        if follow_limit is not None and count >= follow_limit:
            print(f"[INFO] Reached follow limit of {follow_limit}.")
            break

        try:
            url = f"https://graph.facebook.com/{uid}/subscribers"
            payload = {"access_token": token}
            res = httpx.post(url, json=payload)

            try:
                res_json = res.json()
            except ValueError:
                print("[ERROR] Invalid response from Facebook API.")
                continue

            if isinstance(res_json, dict) and res_json.get("success"):
                count += 1
                print(f"[+] Followed ({count}) -> Profile {uid}")
            elif isinstance(res_json, bool) and res_json:
                count += 1
                print(f"[+] Followed ({count}) -> Profile {uid}")
            else:
                print("[RPW FAILURE] Failed to follow:")
                print(res_json)
        except Exception as e:
            print("[ERROR]", e)

# ----------------------------
# Function to auto unfollow a profile given a profile URL or UID.
# ----------------------------
def auto_unfollow(tokens, input_value, unfollow_limit=None):
    """
    Automatically unfollow a profile. The input_value can be either:
      - A full profile URL (like "https://www.facebook.com/profile.php?id=61575358101686")
      - A numeric UID (e.g., "61575358101686")
    The function extracts the UID if needed and then sends an unfollow request using the DELETE method.
    Optionally, a limit on the number of unfollow attempts can be set.
    """
    if input_value.startswith("http"):
        uid = extract_uid(input_value)
    else:
        uid = input_value

    if not uid:
        print("[RPW FAILURE] Could not determine UID for auto unfollow.")
        return

    count = 0
    for token in tokens:
        if unfollow_limit is not None and count >= unfollow_limit:
            print(f"[INFO] Reached unfollow limit of {unfollow_limit}.")
            break

        try:
            url = f"https://graph.facebook.com/{uid}/subscribers"
            # Pass access token as URL parameter
            params = {"access_token": token}
            res = httpx.delete(url, params=params)

            try:
                res_json = res.json()
            except ValueError:
                print("[ERROR] Invalid response from Facebook API.")
                continue

            # Facebook's API might return a success flag or a boolean on DELETE requests.
            if (isinstance(res_json, dict) and res_json.get("success")) or (isinstance(res_json, bool) and res_json):
                count += 1
                print(f"[+] Unfollowed ({count}) -> Profile {uid}")
            else:
                print("[RPW FAILURE] Failed to unfollow:")
                print(res_json)
        except Exception as e:
            print("[ERROR]", e)

# ----------------------------
# Main program to choose actions
# ----------------------------
if __name__ == "__main__":
    try:
        print("AUTO FACEBOOK TOOL (v21.0)")
        print("[1] Auto Share Post")
        print("[2] Auto React to Post")
        print("[3] Auto Follow Profile (by URL or UID)")
        print("[4] Auto Generate Access Token")
        print("[5] Auto Unfollow Profile (by URL or UID)")
        print("[6] Auto Comment on Post")
        choice = input("Choose an option (1/2/3/4/5/6): ").strip()

        tokens_file = "/sdcard/666.txt"
        with open(tokens_file, "r") as f:
            tokens = [line.strip() for line in f.readlines()]

        if choice == "1":
            url = input("Enter Facebook post URL: ").strip()
            auto_share_post(tokens, url)
        elif choice == "2":
            reaction = input("Enter reaction type (LIKE/LOVE/HAHA/WOW/SAD/ANGRY): ").strip().upper()
            target_reactions = int(input("How many reactions to perform? ").strip())
            fb_url = input("Enter Facebook post URL: ").strip()
            auto_react_to_post(tokens, fb_url, reaction, target_reactions)
        elif choice == "3":
            input_value = input("Enter Facebook profile URL or numeric UID to follow: ").strip()
            limit_input = input("Enter follow limit (press Enter for no limit): ").strip()
            follow_limit = int(limit_input) if limit_input.isdigit() else None
            auto_follow(tokens, input_value, follow_limit)
        elif choice == "4":
            user = input("Enter Facebook Email/User ID: ")
            passw = input("Enter Password: ")
            get_access_token(user, passw)
        elif choice == "5":
            input_value = input("Enter Facebook profile URL or numeric UID to unfollow: ").strip()
            limit_input = input("Enter unfollow limit (press Enter for no limit): ").strip()
            unfollow_limit = int(limit_input) if limit_input.isdigit() else None
            auto_unfollow(tokens, input_value, unfollow_limit)
        elif choice == "6":
            fb_url = input("Enter Facebook post URL: ").strip()
            comment_text = input("Enter your comment: ").strip()
            target_comments = int(input("How many comments to perform? ").strip())
            auto_comment_post(tokens, fb_url, comment_text, target_comments)
        else:
            print("[RPW FAILURE] Invalid choice.")
    except KeyboardInterrupt:
        print("\n[RPW FAILURE] Interrupted.")

