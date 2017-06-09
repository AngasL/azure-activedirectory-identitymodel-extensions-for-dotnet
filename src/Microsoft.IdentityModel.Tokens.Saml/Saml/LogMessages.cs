//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591

        // SecurityTokenHandler messages
        internal const string IDX10400 = "IDX10400: The '{0}', can only process SecurityTokens of type: '{1}'. The SecurityToken received is of type: '{2}'.";
        internal const string IDX10721 = "IDX10721: Creating SamlSecurityToken: Issuer: '{0}', Audience: '{1}'";

        // SamlSerializer reading
        internal const string IDX11100 = "IDX11100: Saml Only one element of type '{0}' is supported.";
        internal const string IDX11101 = "IDX11101: Saml Unexpected element found '{0}' while reading.";
        internal const string IDX11102 = "IDX11102: Saml An AuthorizationDecisionStatement must have at least one Action.";
        internal const string IDX11103 = "IDX11103: Saml Evidence must have at least one assertion.";
        internal const string IDX11104 = "IDX11104: Saml Name cannot be null or empty.";
        internal const string IDX11105 = "IDX11105: Saml SubjectConformation Name cannot be null or empty.";
        internal const string IDX11106 = "IDX11106: Saml No SubjectConfirmation clauses were specified.";
        internal const string IDX11107 = "IDX11107: Saml A Subject requires a NameIdentifier or ConfirmationMethod";
        internal const string IDX11108 = "IDX11108: Saml AuthorityBinding.AuthorityKind is not well formed. Is should be of the form str:str, it is '{0}'";
        internal const string IDX11109 = "IDX11109: SamlAssertion.Issuer cannont be null or empty when creating claims.";
        internal const string IDX11110 = "IDX11110: The SamlSecurityToken must have a value for its Assertion property.";

        internal const string IDX11111 = "IDX11111: When reading '{0}', '{1}' was not a Absolute Uri, was: '{2}'.";
        internal const string IDX11112 = "IDX11112: Exception thrown while reading '{0}' for SamlSecurityToken. Inner exception: '{1}'.";
        internal const string IDX11114 = "IDX11114: Unable to read SamlSecurityToken. Expecting XmlReader to be at element: '{0}', found 'Empty Element'";
        internal const string IDX11115 = "IDX11115: Unable to read for SamlSecurityToken. Element: '{0}' as missing Attribute: '{1}'.";
        internal const string IDX11116 = "IDX11116: Unable to read for SamlSecurityToken. MajorVersion must be '1' was: '{0}'.";
        internal const string IDX11117 = "IDX11117: Unable to read for SamlSecurityToken. MinorVersion must be '1' was: '{0}'.";
        internal const string IDX11118 = "IDX11118: Unable to read condition : '{0}'. SamlSecurityToken only support AudienceRestrictionCondition and DoNotCacheCondition.";
        internal const string IDX11119 = "IDX11119: Unable to read for SamlSecurityToken. Element: '{0}' as missing element: '{1}' when reading element: '{2}'.";
        internal const string IDX11120 = "IDX11120: Unable to read for SamlSecurityToken. Element: '{0}' doesn't contain element: '{1}'.";
       // internal const string IDX11120 = "IDX11120: Unable to read SamlSecurityToken. Expecting XmlReader to be at element: '{0}', found 'Empty Element'";

#pragma warning restore 1591
    }
}
