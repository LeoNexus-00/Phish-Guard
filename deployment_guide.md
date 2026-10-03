# How to Make PhishGuard Live on the Internet

Because this project is built using Streamlit, it requires a long-running server. Therefore, we **cannot use Vercel**. Instead, we will use **Streamlit Community Cloud**, which is free and connects directly to GitHub!

## Prerequisite: Your Files
Your project is already 100% ready to be deployed.
Streamlit Cloud only requires two things to exist in your repository:
1. `app.py` (The main script, which you have)
2. `requirements.txt` (The list of libraries, which you also have)

## Step 1: Upload to GitHub
1. Create a free account on [GitHub](https://github.com/).
2. Create a **New Repository** (you can name it `phishguard`).
3. Upload **all** the files and folders from this project folder into that repository.
   *(Make sure `app.py` and `requirements.txt` are at the very top level of the repository, not hidden inside a subfolder).*

## Step 2: Connect to Streamlit Cloud
1. Go to [Streamlit Community Cloud](https://share.streamlit.io/) and click **Sign In**.
2. Sign in using your GitHub account.
3. Once logged in, click the **"New app"** button.
4. If it asks for permission to access your GitHub repositories, click **Authorize**.

## Step 3: Deploy
Streamlit will ask you for 3 pieces of information:
1. **Repository:** Select your `phishguard` repository from the dropdown list.
2. **Branch:** Select `main` (or `master`).
3. **Main file path:** Type `app.py`.

Click **Deploy!**

## Step 4: Wait for the Build
You will see a loading screen with a small terminal on the side.
Streamlit is reading your `requirements.txt` file and installing Python on a secure cloud server for you. This usually takes about 2 to 3 minutes.

## Congratulations!
Once it finishes, your app will appear on the screen! You will be given a public URL (like `https://phishguard.streamlit.app`) that you can share with your friends, your professor, and your viva examiner. 

*Note: Because it is a free server, if nobody visits your app for 7 days, it will "go to sleep". If that happens, simply visit the link yourself and click the "Wake up" button to turn it back on!*
