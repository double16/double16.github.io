---
layout: post
title:  "Creating Personas using AI"
date:   2024-09-12
categories:
  - cyber
  - recon
  - ai
comments: true
---

When working bug bounties, you're going to create users. Some of the profile information can take a minute to think up, at least for me. Now, I've created an AI bot to create personas for me and they are pretty good. I get a name, billing and shipping address, username, password, fake credit card, personal interests, bio, tag lines, a resume and more.

The code is available in my GitHub at [https://github.com/double16/fabric](https://github.com/double16/fabric), the `create_persona` pattern. The pattern is used with [fabric](https://github.com/danielmiessler/fabric), or you can paste the code into the OpenAI AI Assistant.

This pattern requires no input. It will create a persona in a randomly chosen large city. Any input given will influence the results, such as city, personal interests, and the domain name or URL of the target web site. The output is markdown so it will work with a variety of text editors.

# St. Louis, MO

```shell
$ echo "St. Louis, MO" | fabric --pattern create_persona
```

Note that the avatar pictures have been redacted. It will pull pictures of real people and I don't want to post those here.
## Persona Details

- **Name**: Sarah Thompson
- **Gender**: Female
- **Date of Birth**: August 15, 1985
- **Age**: 38
- **Billing Address**:
  - 4567 Pine Street
  - St. Louis, MO 63108
- **Shipping Address**:
  - 4567 Pine Street
  - St. Louis, MO 63108
- **Phone Number**: (314) 555-8392
- **Email**: sarah.thompson@protonmail.com
- **Password**: Th0mP$0n!2023
- **Username**: bluebird85
- **Payment Card**:
  - **Card Type**: Visa
  - **Card Number**: 4111 1111 1111 1111
  - **Expiration Date**: 08/26
  - **CCV**: 456
- **Security Questions**:
  - **Question 1**: What is the name of your first pet?
    - **Answer**: Max
  - **Question 2**: What is your mother's maiden name?
    - **Answer**: Johnson
  - **Question 3**: What was the name of your elementary school?
    - **Answer**: Lincoln Elementary
- **City of Birth**: Kansas City, MO
- **Cities Lived**:
  - **Kansas City, MO** (1985-2003)
  - **Columbia, MO** (2003-2007)
  - **St. Louis, MO** (2007-Present)
- **Education History**:
  - **High School**: Central High School, Kansas City, MO (Graduated 2003)
  - **Bachelor's Degree**: University of Missouri, Columbia, MO (Bachelor of Science in Business Administration, Graduated 2007)
- **Job Title**: Marketing Manager
- **Company**: Gateway Marketing Solutions
- **Work Location**: St. Louis, MO
- **Personal Interests**:
  - Cooking
  - Hiking
  - Photography
  - Movies
- **Personal Bio**:
  - Hey, I'm Sarah! Born and raised in Missouri, I've been living in St. Louis for the past 16 years. I work as a Marketing Manager and love to spend my weekends hiking and capturing the beauty of nature through photography. Big fan of cooking up new recipes and chilling with a good movie.
- **Tag Line**:
  - Always chasing the next adventure and a great photo!
- **Avatar Pictures**:
	- **redacted**
## Professional Resume

### Sarah Thompson

#### Contact Information
- **Address**: 4567 Pine Street, St. Louis, MO 63108
- **Phone**: (314) 555-8392
- **Email**: sarah.thompson@protonmail.com

#### Summary
Experienced Marketing Manager with a demonstrated history of working in the marketing and advertising industry. Skilled in digital marketing, campaign management, and creative strategy. Passionate about hiking, photography, and culinary arts.

#### Education
- **University of Missouri, Columbia, MO**
  - Bachelor of Science in Business Administration
  - Graduated: 2007

#### Professional Experience
- **Gateway Marketing Solutions, St. Louis, MO**
  - Marketing Manager (2015 - Present)
    - Lead and manage a team of 10 marketing professionals.
    - Develop and execute marketing strategies to increase brand awareness and drive sales.
    - Analyze market trends and competitor activities to identify opportunities for growth.
    - Oversee digital marketing campaigns, including social media, email marketing, and SEO.

- **Creative Edge Marketing, St. Louis, MO**
  - Marketing Specialist (2007 - 2015)
    - Assisted in the development and implementation of marketing campaigns.
    - Conducted market research and analysis to support strategic planning.
    - Collaborated with the design team to create promotional materials.

#### Skills
- Digital Marketing
- Campaign Management
- Creative Strategy
- Market Analysis
- Team Leadership
- Social Media Marketing
- SEO

#### Personal Interests
- Cooking
- Hiking
- Photography
- Movies

#### References
Available upon request.

# Seattle, WA - introvert

Let's try creating an introverted persona :)


```shell
$ echo "Seattle, WA. Introvert." | fabric --pattern create_persona
```
## Persona

- **First Name:** Evelyn
- **Last Name:** Thompson
- **Gender:** Female
- **Date of Birth:** May 14, 1987 (Age: 36)
- **Billing Address:**
  - 3921 Pine Street
  - Seattle, WA 98101
- **Shipping Address:**
  - 3921 Pine Street
  - Seattle, WA 98101
- **Phone Number:** (206) 555-7392
- **Email:** evelyn.thompson@seattletech.com
- **Password:** E!v3lynT@2023#
- **Username:** quiettechie87
- **Payment Card:**
  - **Type:** Visa
  - **Number:** 4111 1111 1111 1111
  - **Expiration Date:** 11/25
  - **CCV:** 823
- **Security Questions:**
  - **What is your mother's maiden name?** Anderson
  - **What was the name of your first pet?** Whiskers
  - **What was your first car?** Honda Civic
- **City of Birth:** Portland, OR
- **Cities Lived In:**
  - Portland, OR (1987-2009)
  - Bellevue, WA (2009-2014)
  - Seattle, WA (2014-Present)
- **Education History:**
  - B.S. in Computer Science, University of Oregon, 2005-2009
  - M.S. in Software Engineering, University of Washington, 2009-2011
- **Job Title:** Senior Software Developer
- **Company:** SeattleTech Innovations
- **Work Location:** Seattle, WA
- **Personal Interests:**
  - Reading mystery novels
  - Gardening
  - Coding and tech meetups
- **Personal Bio:** Hey, I'm Evelyn! I love spending quiet evenings at home with a good book or tinkering with the latest tech gadgets. When I'm not coding, you can find me in my garden or at a local meetup. I may be an introvert, but I love learning and connecting with like-minded people.
- **Tag Line:** "Coding by day, reading by night."
- **Avatar Pictures:**
	- **redacted**

## Professional Resume

**Evelyn Thompson**

### Contact Information
- **Address:** 3921 Pine Street, Seattle, WA 98101
- **Phone:** (206) 555-7392
- **Email:** evelyn.thompson@seattletech.com

### Objective
Experienced software developer with a strong background in computer science and software engineering. Seeking to leverage my skills in a senior development role at a forward-thinking tech company.

### Education
- **M.S. in Software Engineering**
  - University of Washington, 2009-2011
- **B.S. in Computer Science**
  - University of Oregon, 2005-2009

### Professional Experience
- **Senior Software Developer**
  - *SeattleTech Innovations, Seattle, WA*
  - January 2014 - Present
  - Developed and maintained multiple high-traffic web applications.
  - Led a team of 5 developers in agile project management.
  - Implemented new features and optimized existing code for better performance.

- **Software Developer**
  - *Tech Solutions, Bellevue, WA*
  - June 2011 - December 2013
  - Worked on backend systems and API integrations.
  - Collaborated with front-end developers to ensure seamless user experiences.
  - Participated in code reviews and contributed to team knowledge sharing.

### Skills
- Programming Languages: Python, JavaScript, C++
- Frameworks: Django, React, Node.js
- Tools: Git, Docker, Jenkins
- Soft Skills: Team Leadership, Problem Solving, Communication

### Personal Interests
- Reading mystery novels
- Gardening
- Coding and tech meetups

### References
Available upon request.

# Other Examples

I could go on for a while, it's kinda fun in a nerdy, introverted sort of way. :D

Here are some other examples I've tried, but without the long output:

- `Atlanta, GA. trip.com` - will produce personas who are interested in travel
- `etsy.com` - crafters unite!
- `Kansas City, MO. minecraft.com` - the other kind of crafters
- `male body builder`
- `age 13`, `age 25`, `age 53`, ...- age specific personas with slang

I hope this makes your bug hunting or other testing more realistic and frees up some time.

