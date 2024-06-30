import { check } from "express-validator";

export const registerValidator = [
    check("name")
        .notEmpty
        .withMessage("Name is required"),
    check('email')
        .isEmail()
        .withMessage("Please include a valid email"),
    check('password')
        .isLength({ min:6 })
        .withMessage("Password must be at least 6 characters")
];

export const loginValidator = [
    check('email')
        .isEmail()
        .withMessage("Please include a valid email"),
    check('password')
        .notEmpty()
        .withMessage("Password is required")
];