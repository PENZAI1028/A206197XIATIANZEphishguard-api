import * as React from 'react';
import { Input } from './input';
import { Button } from './button';
import { Eye, EyeOff } from 'lucide-react';

export interface PasswordInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  showLastChar?: boolean;
  defaultVisible?: boolean;
}

const PasswordInput = React.forwardRef<HTMLInputElement, PasswordInputProps>(
  ({ className, showLastChar = true, defaultVisible = true, ...props }, ref) => {
    const [showPassword, setShowPassword] = React.useState(defaultVisible);
    const [displayValue, setDisplayValue] = React.useState('');
    const [actualValue, setActualValue] = React.useState('');
    const timeoutRef = React.useRef<NodeJS.Timeout | null>(null);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const newValue = e.target.value;
      setActualValue(newValue);

      if (showLastChar && !showPassword && newValue.length > 0) {
        // Show last character, hide the rest
        const masked = '•'.repeat(Math.max(0, newValue.length - 1)) + newValue.slice(-1);
        setDisplayValue(masked);

        // Hide the last character after 1 second
        if (timeoutRef.current) {
          clearTimeout(timeoutRef.current);
        }
        timeoutRef.current = setTimeout(() => {
          setDisplayValue('•'.repeat(newValue.length));
        }, 1000);
      } else if (showPassword) {
        setDisplayValue(newValue);
      } else {
        setDisplayValue('•'.repeat(newValue.length));
      }

      // Call the original onChange if provided
      if (props.onChange) {
        props.onChange(e);
      }
    };

    React.useEffect(() => {
      return () => {
        if (timeoutRef.current) {
          clearTimeout(timeoutRef.current);
        }
      };
    }, []);

    React.useEffect(() => {
      if (showPassword) {
        setDisplayValue(actualValue);
      } else {
        setDisplayValue('•'.repeat(actualValue.length));
      }
    }, [showPassword, actualValue]);

    return (
      <div className="relative">
        <Input
          type={showPassword ? 'text' : 'password'}
          className={className}
          ref={ref}
          {...props}
          value={actualValue}
          onChange={handleChange}
          style={{
            fontSize: '16px', // Prevent zoom on iOS
            letterSpacing: showPassword ? 'normal' : '0.1em',
          }}
        />
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
          onClick={() => setShowPassword(!showPassword)}
          tabIndex={-1}
        >
          {showPassword ? (
            <EyeOff className="h-4 w-4 text-gray-400" />
          ) : (
            <Eye className="h-4 w-4 text-gray-400" />
          )}
          <span className="sr-only">
            {showPassword ? 'Hide password' : 'Show password'}
          </span>
        </Button>
      </div>
    );
  }
);

PasswordInput.displayName = 'PasswordInput';

export { PasswordInput };