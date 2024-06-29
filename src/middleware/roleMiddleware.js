export const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(401).json({ msg: 'Role not authorized for this action' });
        }
        next();
    };
}