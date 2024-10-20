import { verify } from 'jsonwebtoken';

export function authMiddleware(handler) {
  return async (req, res) => {
    try {
      const token = req.cookies.token;

      if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const decoded = verify(token, process.env.JWT_SECRET);
      req.userId = decoded.userId;

      return handler(req, res);
    } catch (error) {
      console.error('Authentication error:', error);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}