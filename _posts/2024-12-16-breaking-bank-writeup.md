---
layout: post
title: Breaking Bank Writeup
date: 2024-12-16 11:57 +1100
categories: [CTF-Writeup, Binary-Badlands]
tags: [web, ctf, htb-ctf]
---
This was the first challenge I solved in the 2024 University CTF, and it is an easy web challenge.

Upon opening the webapp, we see a login page, and a notification telling us to claim some money.
![Desktop View](/assets/img/writeup/20241216121443.png)

Lets start by creating an account and logging in:
![Desktop View](/assets/img/writeup/20241216121654.png)

We are presented with these functionalities. The only two that seem to do anything are the Friends, and Transactions functionalities. Before examining these further, lets look at the notification from earlier, but upon clicking the "Claim Your $13.37" link we are redirected to a rickroll.

Lets look closer at this. If we intercept this request, we see:
![Desktop View](/assets/img/writeup/20241216122044.png)

It seems there is a redirect functionality within the website itself. We can abuse this to redirect users to any website, which may be useful later.

### Source Code Analysis

![Desktop View](/assets/img/writeup/20241216122450.png)

The website seems to be using a vite frontend with a node js backend. 

We can find the file `flagService.js`,  which will give us the flag if the financial controller's account as 0 or less CLCR coins:
![Desktop View](/assets/img/writeup/20241216122754.png)

As this mostly means we will want to pose as the financial controller, we can see how our sessions are managed.
Upon looking at our local storage, we see that we have a JWT, which when decoded shows:
![Desktop View](/assets/img/writeup/20241216123041.png)

We can see that the website is using JWKS to verify the JWTs. Lets look at how the application itself handles this, as if we are able to provide our own website in the jku field, we may be able to forge JWT's. 

Looking at the `verifyToken` function in `jwksService.js`, we see that the service is only checking the domain of the jku. 
![Desktop View](/assets/img/writeup/20241216123543.png)

If we are able to have a route on the webapp point to our own JWKS, we will be able to forge a JWT. We can abuse the redirect from earlier to achieve this. Some other considerations in the `verifyToken` function are that we need our `kid` to match the webapp's `kid`, which we can find in the `.well-known/jwks.json` service. We also need to use the `RS256` algorithm.

To create our JWKS, we can use the `JWT Editor` extension from the Burpsuite App store.
Lets create a new RSA key, using the same `kid` as the website:
![Desktop View](/assets/img/writeup/20241216124047.png)

After generating the key, we can copy the public key as a JWK by right clicking on the key, and host it as a JWKS on our own web server.
This is what the self-hosted JWKS should look like (the format should follow the same as the websites jwks):
![Desktop View](/assets/img/writeup/20241216125548.png)


Now we can forge our JWT.
By going to a burpsuite repeater tab with a JWT, we can access the JWT Editor extension.
![Desktop View](/assets/img/writeup/20241216124859.png)
_Valid JWT_

Lets change the `jku` route to a redirect pointing at our hosted JWKS, and change the email to the Financial Controller email.

![Desktop View](/assets/img/writeup/20241216125147.png)
_Forged JWT signed with our private key_

We can copy this forged JWT and paste it into our browser's local history, which will give us access to the admin's account.
![Desktop View](/assets/img/writeup/20241216125732.png)

Next we need to move of the admin's CLCR coins to our account.

After adding our account as a friend, we can attempt to transfer the coins, but we encounter a problem:
![Desktop View](/assets/img/writeup/20241216130004.png)

Lets look at the logic handling this:
![Desktop View](/assets/img/writeup/20241216130120.png)

In the function `otpMiddleware`, we can observe that website attempts to validate the otp by checking if it includes the valid otp. By intercepting a request, we see that the otp is being sent as an element of an array. We can attack this by sending an array of all possible otp's, so that it will always include the valid otp. By examining the otp generation logic we see that an otp is a number between 1000 and 9999.

![Desktop View](/assets/img/writeup/20241216130609.png)

This will print out these numbers in JSON format.

![Desktop View](/assets/img/writeup/20241216130722.png)

The request body  will look like this.

When sending this off, we get a successful response, and upon checking the homepage on our account:
![Desktop View](/assets/img/writeup/20241216130823.png)

We get the flag!

