import type { NextAuthConfig } from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email:string): Promise<User | undefined>{
    try {
        const user = await sql<User> `SELECT * FROM user WHERE email=${email}`;
        return user.rows[0];
    } catch (error) {
        console.error('Failed to fetch uer:', error);
        throw new Error("Failed to fetch user.");
        
    }
}

 
export const authConfig = {
  pages: {
    signIn: '/login',
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard');
      if (isOnDashboard) {
        if (isLoggedIn) return true;
        return false; // Redirect unauthenticated users to login page
      } else if (isLoggedIn) {
        return Response.redirect(new URL('/dashboard', nextUrl));
      }
      return true;
    },
  },
  providers: [Credentials({
    async authorize(credentials){
        const parsedCredentials = z.object({ email: z.string().email(), password: z.string().min(6) }).safeParse(credentials);

        if (parsedCredentials.success) {
            const { email, password } = parsedCredentials.data;
            const user  = await getUser(email);
            if (!user) return null;

            const passwordMatched = await bcrypt.compare(password, user.password);

            if (passwordMatched) return user;
        }
 
        console.log("Invalid Credentials");
        return null;
    }
  })], // Add providers with an empty array for now
} satisfies NextAuthConfig;