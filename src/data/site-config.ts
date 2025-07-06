export type Image = {
    src: string;
    alt?: string;
    caption?: string;
};

export type Link = {
    text: string;
    href: string;
};

export type Hero = {
    title?: string;
    text?: string;
    image?: Image;
    actions?: Link[];
};

export type Subscribe = {
    title?: string;
    text?: string;
    formUrl: string;
};

export type SiteConfig = {
    website: string;
    logo?: Image;
    title: string;
    subtitle?: string;
    description: string;
    image?: Image;
    headerNavLinks?: Link[];
    footerNavLinks?: Link[];
    socialLinks?: Link[];
    hero?: Hero;
    subscribe?: Subscribe;
    postsPerPage?: number;
    projectsPerPage?: number;
};

const siteConfig: SiteConfig = {
    website: 'https://example.com',
    title: 'Dante',
    subtitle: 'Minimal Astro.js theme',
    description: 'Astro.js and Tailwind CSS theme for blog and portfolio by justgoodui.com',
    image: {
        src: '/dante-preview.jpg',
        alt: 'Dante - Astro.js and Tailwind CSS theme'
    },
    headerNavLinks: [
        {
            text: 'Home',
            href: '/'
        },
        {
            text: 'Projects',
            href: '/projects'
        }
    ],
    footerNavLinks: [

    ],
    socialLinks: [
        {
            text: 'LinkedIn',
            href: 'https://www.linkedin.com/in/flainvar/'
        },
    ],
    hero: {
        title: 'Portafolio de ciberseguridad.',
        text: "¡Hola! Bienvenidos a mi portafolios, aquí podrás aprender junto a mí sobre análisis de seguridad defensiva. Tras mi etapa universitaria -estudiando sociología- decidí dedicarme a una de mis pasiones tempranas: la informática. Así, me matriculé en el Grado Superior de ASIR a la par que estudio, de manera autodidáctica, ciberseguridad con herramientas online como HackTheBox. Mi objetivo actual es la certificación de CDSA.",
        image: {
            src: '/curro.png',
            alt: 'A person sitting at a desk in front of a computer'
        },
    },

    postsPerPage: 8,
    projectsPerPage: 8
};

export default siteConfig;
