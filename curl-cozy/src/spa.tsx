import { createRoot } from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';
import { getRouter } from './router';
import './styles.css';
// The shared providers, routes and inspector shell are unchanged.
const router = getRouter();
void router.load().then(() => createRoot(document.getElementById('root')!).render(<RouterProvider router={router} />));
