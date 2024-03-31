+++
title = 'Fuck_Web_Dev'
date = 2024-03-30T15:58:47-04:00
tags= ["shit posting"]
draft = false
+++


**CSH Major Project**

As a member of the Computer Science House(CSH) at RIT we have a yearly major project that is required. This year I wanted to create a shopping cart dispensory but I fucked up ordering parts so that idea got scrapped. Then I wanted to 3D print a dactyl manuform and soudder all the pins myself. Same issue no time to order parts. So I did what any other sane person would do, I wrote a personal site. That is the site you are looking at right now

**Purpose of Website**

I wanted to create a personal site mainly host my technical Capture the Flag writeups and showcase some projets I've worked on. I got inspired to create this website when I was switching from i3 and Xorg to Hyprland and Wayland and saw a blog site that had the exact error I had but was the only site. I want to expand the scope of my site to include snippets of code or debugging issues that I run into in the hopes of helping others. Overtime I want to expand the content to not just technical writeups, I'm a die hard member of the Cult of Vi and I would love to share resources to help people get into Vim. I'm also very big on linux RICEing, setting up a tiling window manager and status bar is something I would love to write about in depth.


**The Process**

First things first the design of the website comes from Andy(Cherry), he created a skeleton in Figma in 10 minutes and that is what I based my website off of. Personally I loved the design that Andy created so I based my website heavily off [this](https://www.figma.com/file/X6nMaED81efS0JtM9aLtYW/eddie-blog-(Copy)?type=design&node-id=0-1&mode=design&t=9cqGyutwrFgEtH8I-0). I used [Hugo](https://gohugo.io/) for the site generation as Hugo is able to take templates and convert markdown to blog pages. This fits my use case perfectly as I want to write my CSS/HTML templates once and never touch them again. I have taken a web development class before in the past but I pride myself on passing the class without writing any CSS. From that class I grew a burning hatred for web developemnt espically front end. So my delusional ass decided that it would be a good idea to write all the CSS myself and not use a Hugo theme. And now that monstrosity lives [here](https://isnis.csh.rit.edu/css/style.css)

**What I learned** 

FUCK WEB DEVELOPMENT. This shit sucks so much. Flex or Grid box??? No y'all can all fuck off. This shit ain't a programming lanauge for a reason. Tweaking any slight bit of CSS makes it just shit itself and break the site. Maybe it's a skill issue cause I'm just bad at it but I don't see how this shit can be enjoyable. Cascading Style Sheets? More like Cursed Styles Shit. I think I can rant on and on about how much I hate this. Oh mobile too. WTF scaling and being mobile friendly is hard. I realized how fucked my site looked on mobile as I pinned the nav bar to the left of the screen. Apparently I'm supposed to figure that shit out and check if we're on a mobile device and rerender accordingly. You know what? Fuck that! Check this site out on a mobile device and you will see my easter egg.

Moving on! Hugo. Hugo was an amazing framework to work with as it was very intuitive and had great templating support. It supports Go snippets in the code to make some very dynamic statically generated sites. It sorta just worked most of the time. Except one time where I had some routing bullshit with Nginx. I set a path to /about which caused Nginx to change the port of the request which made the request invalid. Like WTF?? I don't think this was even a Hugo issue, mainly just Nginx acting funky. The solution to this is to set the path to "/about/" which solved this.


**Conslusion**

I hope that I never have to write another line of CSS. Cursed Styles Shit is so fucking bad. I hope these tempaltes continue working so I don't have to maintain them. I pray Chrome and Firefox don't change their rendering engine anytime soon.


Thanks for Reading! Goodbye World!
